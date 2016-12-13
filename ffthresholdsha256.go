package cryptoconditions

import (
	"bytes"
	"encoding/binary"
	"math"
	"sort"

	"github.com/pkg/errors"
)

const (
	ffThresholdSha256Features Features = FSha256 | FThreshold

	// maxWeight specifies the maximum value for a weight, which is the maximum value for a uint32.
	// We use it here to denote "infinity" or a larger weight than any other.
	maxWeight = uint32(math.MaxUint32)
)

//TODO do we really need to incorporate for unfulfilled ones? it makes this file so much more complicated

// FfThresholdSha256 implements the Threshold-SHA-256 fulfillment.
type FfThresholdSha256 struct {
	threshold uint32

	subFfs []*weightedSubFulfillment
}

// weightedFulfillment represent a Fulfillment and a corresponding weight.
type weightedSubFulfillment struct {
	weight      uint32
	isFulfilled bool
	// ff holds a fulfillment if isFulfilled is true, nil otherwise
	ff Fulfillment
	// cond holds a *Condition if isFulfilled is false, nil otherwise
	cond *Condition
}

// Condition returns the condition this sub-fulfillment represents.
func (sff *weightedSubFulfillment) Condition() (*Condition, error) {
	if sff.isFulfilled {
		return sff.ff.Condition()
	} else {
		return sff.cond, nil
	}
}

// weightedFulfillments is a slice of weightedFulfillments that implements sort.Interface to
// sort them by weight in descending order.
type weightedSubFulfillmentSorter []*weightedSubFulfillment

func (w weightedSubFulfillmentSorter) Len() int           { return len(w) }
func (w weightedSubFulfillmentSorter) Less(i, j int) bool { return w[j].weight < w[i].weight }
func (w weightedSubFulfillmentSorter) Swap(i, j int)      { w[i], w[j] = w[j], w[i] }

// NewFfThresholdSha256 creates a new FfThresholdSha256 fulfillment.
//TODO do we need to allow adding unfulfilled conditions here too? look at JS later
func NewFfThresholdSha256(threshold uint32, subFulfillments []Fulfillment, weights []uint32) (*FfThresholdSha256, error) {
	if len(subFulfillments) != len(weights) {
		return nil, errors.New("Not the same amount of sub-fulfillments and weights provided.")
	}

	// merge the fulfillments with the weights and sort them
	subFfs := make([]*weightedSubFulfillment, len(subFulfillments))
	for i, ff := range subFulfillments {
		subFfs[i] = &weightedSubFulfillment{weight: weights[i], isFulfilled: true, ff: ff}
	}
	// cast to weightedSubFulfillmentSorter to be able to sort
	sorter := weightedSubFulfillmentSorter(subFfs)
	sort.Sort(sorter)

	return &FfThresholdSha256{
		threshold: threshold,
		subFfs:    subFfs,
	}, nil
}

func (ff *FfThresholdSha256) Type() ConditionType {
	return CTThresholdSha256
}

// Threshold returns the threshold used in this fulfillment.
func (ff *FfThresholdSha256) Threshold() uint32 {
	return ff.threshold
}

func (ff *FfThresholdSha256) Condition() (*Condition, error) {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, ff.threshold)
	writeVarUInt(buffer, len(ff.subFfs))
	for _, sff := range ff.subFfs {
		if err := writeVarUInt(buffer, int(sff.weight)); err != nil {
			return nil, errors.Wrap(err, "Failed to write VarUInt")
		}
		sffCond, err := sff.Condition()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to generate condition of sub-fulfillment")
		}
		if err := SerializeCondition(buffer, sffCond); err != nil {
			return nil, errors.Wrap(err, "Failed to serialize condition of sub-fulfillment")
		}
	}
	fingerprint := buffer.Bytes()

	features, err := ff.getFeatures()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct feature bitmask")
	}

	maxFfLength, err := ff.calculateMaxFulfillmentLength()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to calculate max fulfillment length")
	}

	return NewCondition(CTThresholdSha256, features, fingerprint, maxFfLength), nil
}

// weightedFulfillmentInfo is a weightedFulfillment with some of its info cached for use by
// calculateSmallestValidFulfillmentSet
type weightedSubFulfillmentInfo struct {
	*weightedSubFulfillment
	// the index in the original ff set of the ff this info corresponds to
	index int
	// the size of the fulfillment to be included and the size of the condition in the case it's not
	size, omitSize uint32
}

// weightedFulfillments is a slice of weightedFulfillments that implements sort.Interface to
// sort them by weight in descending order.
type weightedSubFulfillmentInfoSorter []*weightedSubFulfillmentInfo

func (w weightedSubFulfillmentInfoSorter) Len() int           { return len(w) }
func (w weightedSubFulfillmentInfoSorter) Less(i, j int) bool { return w[j].weight < w[i].weight }
func (w weightedSubFulfillmentInfoSorter) Swap(i, j int)      { w[i], w[j] = w[j], w[i] }

// State object used for the calculation of the smallest valid set of fulfillments.
type smallestValidFulfillmentSetCalculatorState struct {
	index int
	size  uint32
	set   []int
}

// hasIndex checks if a certain fulfillment index is in smallestValidFulfillmentSetCalculator.set
func (c smallestValidFulfillmentSetCalculatorState) hasIndex(idx int) bool {
	for _, v := range c.set {
		if v == idx {
			return true
		}
	}
	return false
}

// calculateSmallestValidFulfillmentSet calculates the smallest valid set of sub-fulfillments that reach the given
// threshold. The method works recursively and keeps the state of the current recursion in the a
// smallestValidFulfillmentSetCalculatorState object.
func calculateSmallestValidFulfillmentSet(threshold uint32, sffs []*weightedSubFulfillmentInfo,
	state *smallestValidFulfillmentSetCalculatorState) (*smallestValidFulfillmentSetCalculatorState, error) {
	// Threshold reached, so the set we have is enough.
	if threshold <= 0 {
		return &smallestValidFulfillmentSetCalculatorState{
			size: state.size,
			set:  state.set,
		}, nil
	}

	// We iterated through the list of sub-fulfillments and we did not find a valid set -> impossible.
	if state.index >= len(sffs) {
		return &smallestValidFulfillmentSetCalculatorState{
			size: maxWeight,
		}, nil
	}

	// Regular case: we calculate the set if we would include or not include the next sub-fulfillment
	// and then pick the choice with the lowest size.
	nextSff := sffs[state.index]

	withoutNext, err := calculateSmallestValidFulfillmentSet(
		threshold,
		sffs,
		&smallestValidFulfillmentSetCalculatorState{
			index: state.index + 1,
			size:  state.size + nextSff.omitSize,
			set:   state.set,
		},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to calculate smallest valid fulfillment set (without index %v)", state.index)
	}

	// If not fulfilled, we can only consider the case to not include it.
	if !nextSff.isFulfilled {
		return withoutNext, nil
	}

	withNext, err := calculateSmallestValidFulfillmentSet(
		threshold-nextSff.weight,
		sffs,
		&smallestValidFulfillmentSetCalculatorState{
			index: state.index + 1,
			size:  state.size + nextSff.size,
			set:   append(state.set, nextSff.index),
		},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to calculate smallest valid fulfillment set (with index %v", state.index)
	}

	// return the smallest
	if withNext.size < withoutNext.size {
		return withNext, nil
	} else {
		return withoutNext, nil
	}
}

func (ff *FfThresholdSha256) Payload() ([]byte, error) {
	//TODO if we don't keep the cache, but build the either the condition or the fulfillment another time
	// at the end, we could reuse the write code from the calculateFulfillmentLength method

	// Build a cache with the relevant information for the calculation.
	sffs := make([]*weightedSubFulfillmentInfo, len(ff.subFfs))
	sffsCachedBytes := make([][][]byte, len(ff.subFfs))
	for i, sff := range ff.subFfs {
		// size: serialize fulfillment (can only do this when we have it)
		var sffBytes []byte
		if sff.isFulfilled {
			buffer := new(bytes.Buffer)
			if err := SerializeFulfillment(buffer, sff.ff); err != nil {
				return nil, errors.Wrap(err, "Failed to serialize sub-fulfillment")
			}
			sffBytes = buffer.Bytes()
		}
		// omit size: serialize condition
		sffCond, err := sff.Condition()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to generate condition of sub-fulfillment")
		}
		buffer := new(bytes.Buffer)
		if err := SerializeCondition(buffer, sffCond); err != nil {
			return nil, errors.Wrap(err, "Failed to serialize condition of sub-filfillment")
		}
		sffCondBytes := buffer.Bytes()

		sffs[i] = &weightedSubFulfillmentInfo{
			weightedSubFulfillment: sff,
			index:    i,
			size:     uint32(len(sffBytes)),
			omitSize: uint32(len(sffCondBytes)),
		}
		sffsCachedBytes[i] = [][]byte{
			sffBytes,
			sffCondBytes,
		}
	}

	// Calculate the smallest valid set of fulfillments.
	smallestSet, err := calculateSmallestValidFulfillmentSet(
		ff.threshold,
		sffs,
		&smallestValidFulfillmentSetCalculatorState{
			index: 0,
			size:  0,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to calculate smallest valid fulfillment set")
	}

	// Save the serialization or the condition depending on whether or not a sub-fulfillment
	// is included in the smallest set.
	var serializations sortableByteSlices
	for i, sff := range sffs {
		buffer := new(bytes.Buffer)
		if err := writeVarUInt(buffer, int(sff.weight)); err != nil {
			return nil, errors.Wrap(err, "Failed to write VarUInt")
		}
		var ffToWrite, condToWrite []byte
		// Either fill ffToWrite or condToWrite depending on whether or not the ff is included.
		if smallestSet.hasIndex(i) {
			ffToWrite = sffsCachedBytes[i][0]
			condToWrite = nil
		} else {
			ffToWrite = nil
			condToWrite = sffsCachedBytes[i][1]
		}
		// We have to write 2 octet strings, but one of them will be empty.
		if err := writeOctetString(buffer, ffToWrite); err != nil {
			return nil, errors.Wrap(err, "Failed to write octet string of sub-fulfillment")
		}
		if err := writeOctetString(buffer, condToWrite); err != nil {
			return nil, errors.Wrap(err, "Failed to write octet string of sub-condition")
		}
		serializations = append(serializations, buffer.Bytes())
	}
	// sort the serializations lexicographically
	sort.Sort(serializations)

	// serialize everything
	buffer := new(bytes.Buffer)
	if err := writeVarUInt(buffer, int(ff.threshold)); err != nil {
		return nil, errors.Wrapf(err, "Failed to write VarUInt of threshold (%v)", int(ff.threshold))
	}
	if err := writeVarUInt(buffer, len(serializations)); err != nil {
		return nil, errors.Wrapf(err, "Faield to write VarUInt of nb of sub-fulfillments (%v)", len(serializations))
	}
	for _, s := range serializations {
		if _, err := buffer.Write(s); err != nil {
			return nil, errors.Wrapf(err, "Failed to write serialization of length %v", len(s))
		}
	}
	return buffer.Bytes(), nil
}

func (ff *FfThresholdSha256) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	var err error
	if threshold, err := readVarUInt(reader); err != nil {
		return errors.Wrap(err, "Failed to read VarUInt of threshold")
	} else {
		ff.threshold = uint32(threshold)
	}
	nbFfs, err := readVarUInt(reader)
	if err != nil {
		return errors.Wrap(err, "Failed to read VarUInt of sub-fulfillment count")
	}

	ff.subFfs = make([]*weightedSubFulfillment, nbFfs)
	for i := 0; i < nbFfs; i++ {
		weight, err := readVarUInt(reader)
		if err != nil {
			return errors.Wrap(err, "Failed to read VarUInt of sub-fulfillment weight")
		}
		ffBytes, err := readOctetString(reader)
		if err != nil {
			return errors.Wrap(err, "Failed to read octet string of sub-fulfillment")
		}
		condbytes, err := readOctetString(reader)
		if err != nil {
			return errors.Wrap(err, "Failed to read octet string of sub-condition")
		}

		if len(ffBytes) > 0 && len(condbytes) > 0 {
			return errors.New("Subfulfillments may not provide both condition and fulfillment.")
		} else if len(ffBytes) > 0 {
			sff, err := DeserializeFulfillment(bytes.NewReader(ffBytes))
			if err != nil {
				return errors.Wrap(err, "Failed to deserialize sub-fulfillment")
			}
			ff.subFfs[i] = &weightedSubFulfillment{
				weight:      uint32(weight),
				isFulfilled: true,
				ff:          sff,
			}
		} else if len(condbytes) > 0 {
			sc, err := DeserializeCondition(bytes.NewReader(condbytes))
			if err != nil {
				return errors.Wrap(err, "Failed to deserialize sub-condition")
			}
			ff.subFfs[i] = &weightedSubFulfillment{
				weight:      uint32(weight),
				isFulfilled: false,
				cond:        sc,
			}
		} else {
			return errors.New("Subconditions must provide either sub-condition or fulfillment.")
		}
	}

	return nil
}

func (ff *FfThresholdSha256) Validate(message []byte) error {
	// Calculate minimum and total weight.
	minWeight := maxWeight
	var totalWeight uint32
	for _, sff := range ff.subFfs {
		if sff.weight < minWeight {
			minWeight = sff.weight
		}
		totalWeight += sff.weight
	}

	// Total weight must meet the threshold.
	if totalWeight < ff.threshold {
		return errors.New("Total weight of sub-fulfillments is lower than threshold.")
	}

	// But the set must be minimal, there mustn't be any fulfillments we could take out
	if ff.threshold+minWeight <= totalWeight {
		return errors.New("Fulfillment is not minimal.")
	}

	// Validate all sub-fulfillments individually.
	for _, sff := range ff.subFfs {
		if err := sff.ff.Validate(message); err != nil {
			return errors.Wrapf(err, "Failed to validate sub-fulfillment for message %x", message)
		}
	}
	return nil
}

func (ff *FfThresholdSha256) String() string {
	uri, err := Uri(ff)
	if err != nil {
		return "!Could not generate Fulfillment's URI!"
	}
	return uri
}

func (ff *FfThresholdSha256) calculateMaxFulfillmentLength() (uint32, error) {
	// build a list with the fulfillment infos needed for the calculation
	sffs := make([]*weightedSubFulfillmentInfo, len(ff.subFfs))
	for i, sff := range ff.subFfs {
		// size: serialize fulfillment (can only do this when we have it)
		var size uint32
		if sff.isFulfilled {
			counter := new(writeCounter)
			if err := SerializeFulfillment(counter, sff.ff); err != nil {
				return 0, errors.Wrap(err, "Failed to serialize sub-fulfillment")
			}
			size = uint32(counter.Counter())
		}

		// omit size: serialize condition
		sffCond, err := sff.Condition()
		if err != nil {
			return 0, errors.Wrap(err, "Failed to generate condition of sub-fulfillment")
		}
		counter := new(writeCounter)
		if err := SerializeCondition(counter, sffCond); err != nil {
			return 0, errors.Wrap(err, "Failed to serialize condition of sub-filfillment")
		}
		omitSize := uint32(counter.Counter())

		sffs[i] = &weightedSubFulfillmentInfo{
			weightedSubFulfillment: sff,
			index:    i,
			size:     uint32(size),
			omitSize: uint32(omitSize),
		}
	}

	// cast to weightedFulfillmentInfoSorter so that we can sort by weight
	sorter := weightedSubFulfillmentInfoSorter(sffs)
	sort.Sort(sorter)

	sffsWorstLength, err := calculateWorstCaseSffsSize(ff.threshold, sffs, 0)

	if err != nil {
		return 0, errors.New("Insufficient subconditions/weights to meet the threshold.")
	}

	// calculate the size of the remainder of the fulfillment
	counter := new(writeCounter)
	// JS counts threshold as uint32 instead of VarUInt
	counter.Skip(4)
	writeVarUInt(counter, len(ff.subFfs))
	for _, sff := range ff.subFfs {
		// features bitmask is 1 byte
		counter.Skip(1)
		if sff.weight != 1 {
			// weight is uint32, so 4 bytes
			counter.Skip(4)
		}
	}
	// add the worst case total length of the serialized fulfillments and conditions
	counter.Skip(int(sffsWorstLength))

	return uint32(counter.Counter()), nil
}

// calculateWorstCaseSffsSize used in the calculation below
var calculateWorstCaseSffsSizeError = errors.New("Unable to canculate size")

// calculateWorstCaseSffsLength returns the worst case total length of the sub-fulfillments.
// The weighted sub-fulfillments must be ordered by weight descending.
// It returns any error when it was impossible to find one.
func calculateWorstCaseSffsSize(threshold uint32, sffs []*weightedSubFulfillmentInfo, index int) (uint32, error) {
	if threshold <= 0 {
		// threshold reached, no additional fulfillments need to be added
		return 0, nil
	} else if index < len(sffs) {
		// calculate whether including or excluding the fulfillment increases the size the most
		nextFf := sffs[index]

		remainingSizeWithoutNext, errWithout := calculateWorstCaseSffsSize(
			threshold, sffs, index+1)
		sizeWithoutNext := nextFf.omitSize + remainingSizeWithoutNext

		// if sub-fulfillment is not fulfilled, we can only do without
		if !nextFf.isFulfilled {
			if errWithout != nil {
				return 0, calculateWorstCaseSffsSizeError
			} else {
				return sizeWithoutNext, nil
			}
		}

		remainingSizeWithNext, errWith := calculateWorstCaseSffsSize(
			subOrZero(threshold, nextFf.weight), sffs, index+1)
		sizeWithNext := nextFf.size + remainingSizeWithNext

		if errWith != nil && errWithout != nil {
			return 0, calculateWorstCaseSffsSizeError
		} else if errWith != nil {
			return sizeWithoutNext, nil
		} else if errWithout != nil {
			return sizeWithNext, nil
		} else {
			return maxUint32(sizeWithNext, sizeWithoutNext), nil
		}
	} else {
		return 0, calculateWorstCaseSffsSizeError
	}
}

func (ff *FfThresholdSha256) getFeatures() (Features, error) {
	features := ffThresholdSha256Features
	for _, sff := range ff.subFfs {
		condition, err := sff.Condition()
		if err != nil {
			return 0, errors.Wrap(err, "Failed to generate condition of sub-fulfillment")
		}
		features |= condition.Features
	}
	return features, nil
}
