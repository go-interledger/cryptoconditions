package cryptoconditions

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

const (
	ffThresholdSha256Features Features = FSha256 | FThreshold

	// maxWeight specifies the maximum value for a weight, which is the maximum value for a uint32.
	// We use it here to denote "infinity" or a larger weight than any other.
	maxWeight = uint32(math.MaxUint32)
)

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

// weightedFulfillments is a slice of weightedFulfillments that implements sort.Interface
type weightedSubFulfillmentSorter []*weightedSubFulfillment

func (w weightedSubFulfillmentSorter) Len() int           { return len(w) }
func (w weightedSubFulfillmentSorter) Less(i, j int) bool { return w[i].weight < w[j].weight }
func (w weightedSubFulfillmentSorter) Swap(i, j int)      { w[i], w[j] = w[j], w[i] }

// Create a new FfThresholdSha256 fulfillment.
//TODO do we need to allow adding unfulfilled conditions here too? look at JS later
func NewFfThresholdSha256(threshold uint32, subFulfillments []Fulfillment, weights []int) (*FfThresholdSha256, error) {
	if len(subFulfillments) != len(weights) {
		return nil, errors.New("Not the same amount of subfulfillments and weights provided.")
	}

	// merge the fulfillments with the weights and sort them
	subFfs := make([]*weightedSubFulfillment, len(subFulfillments))
	for i, ff := range subFulfillments {
		subFfs[i] = &weightedSubFulfillment{weight: uint32(weights[i]), isFulfilled: true, ff: ff}
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

func (ff *FfThresholdSha256) Condition() (*Condition, error) {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, ff.threshold)
	writeVarUInt(buffer, len(ff.subFfs))
	for _, sff := range ff.subFfs {
		if err := writeVarUInt(buffer, int(sff.weight)); err != nil {
			return nil, err
		}
		sffCond, err := sff.ff.Condition()
		if err != nil {
			return nil, err
		}
		if err := SerializeCondition(buffer, sffCond); err != nil {
			return nil, err
		}
	}
	fingerprint := buffer.Bytes()

	features, err := ff.getFeatures()
	if err != nil {
		return nil, err
	}

	maxFfLength, err := ff.calculateMaxFulfillmentLength()
	if err != nil {
		return nil, err
	}

	return NewCondition(CTThresholdSha256, features, fingerprint, maxFfLength), nil
}

// State object used for the calculation of the smallest valid set of fulfillments.
type smallestValidFulfillmentSetCalculator struct {
	index int
	size  uint32
	set   []int
}

// hasIndex checks if a certain fulfillment index is in smallestValidFulfillmentSetCalculator.set
func (c smallestValidFulfillmentSetCalculator) hasIndex(idx int) bool {
	for _, v := range c.set {
		if v == idx {
			return true
		}
	}
	return false
}

// weightedFulfillmentInfo is a weightedFulfillment with some of its info cached for use by
// calculateSmallestValidFulfillmentSet
type weightedFulfillmentInfo struct {
	*weightedSubFulfillment
	// the index in the original ff set of the ff this info corresponds to
	index int
	// the size of the fulfillment to be included and the size of the condition in the case it's not
	size, omitSize uint32
}

// weightedFulfillments is a slice of weightedFulfillments that implements sort.Interface
type weightedFulfillmentInfoSorter []*weightedFulfillmentInfo

func (w weightedFulfillmentInfoSorter) Len() int           { return len(w) }
func (w weightedFulfillmentInfoSorter) Less(i, j int) bool { return w[i].weight < w[j].weight }
func (w weightedFulfillmentInfoSorter) Swap(i, j int)      { w[i], w[j] = w[j], w[i] }

func calculateSmallestValidFulfillmentSet(threshold uint32, ffs []*weightedFulfillmentInfo,
	state *smallestValidFulfillmentSetCalculator) (*smallestValidFulfillmentSetCalculator, error) {
	//TODO consider an approach where we don't "build a set", but just iterate over the slice
	// and set a bool to true if we want it in or false for out
	// we can even incorporate that in the serialize process..
	if threshold <= 0 {
		return &smallestValidFulfillmentSetCalculator{
			size: state.size,
			set:  state.set,
		}, nil
	}
	if state.index >= len(ffs) {
		return &smallestValidFulfillmentSetCalculator{
			size: maxWeight,
		}, nil
	}

	nff := ffs[state.index]

	withNext, err := calculateSmallestValidFulfillmentSet(
		threshold-nff.weight,
		ffs,
		&smallestValidFulfillmentSetCalculator{
			index: state.index + 1,
			size:  state.size + nff.size,
			set:   append(state.set, nff.index),
		},
	)
	if err != nil {
		return nil, err
	}

	withoutNext, err := calculateSmallestValidFulfillmentSet(
		threshold,
		ffs,
		&smallestValidFulfillmentSetCalculator{
			index: state.index + 1,
			size:  state.size + nff.omitSize,
			set:   state.set,
		},
	)
	if err != nil {
		return nil, err
	}

	// return the smallest
	if withNext.size < withoutNext.size {
		return withNext, nil
	} else {
		return withoutNext, nil
	}
}

// sortableByteSlices is a slice of byte slices that implements sort.Interface
type sortableByteSlices [][]byte

func (s sortableByteSlices) Len() int           { return len(s) }
func (s sortableByteSlices) Less(i, j int) bool { return bytes.Compare(s[i], s[j]) < 0 }
func (s sortableByteSlices) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (ff *FfThresholdSha256) Payload() ([]byte, error) {
	// we build a cache with the relevant information for the calculation
	sffs := make([]*weightedFulfillmentInfo, len(ff.subFfs))
	sffsCachedBytes := make([][][]byte, len(ff.subFfs))
	for i, sff := range ff.subFfs {
		// size: serialize fulfillment
		buffer := new(bytes.Buffer)
		if err := SerializeFulfillment(buffer, sff.ff); err != nil {
			return nil, err
		}
		sffBytes := buffer.Bytes()
		// omit size: serialize condition
		sffCond, err := sff.ff.Condition()
		if err != nil {
			return nil, err
		}
		buffer = new(bytes.Buffer)
		if err := SerializeCondition(buffer, sffCond); err != nil {
			return nil, err
		}
		sffCondBytes := buffer.Bytes()

		sffs[i] = &weightedFulfillmentInfo{
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

	// we calculate the smallest set of valid fulfillments
	smallestSet, err := calculateSmallestValidFulfillmentSet(
		ff.threshold,
		sffs,
		&smallestValidFulfillmentSetCalculator{
			index: 0,
			size:  0,
		},
	)
	if err != nil {
		return nil, err
	}

	// save the serialization or the condition depending on whether or not a subfulfillment
	// in included in the smallest set
	var serializations sortableByteSlices
	for i, sff := range sffs {
		buffer := new(bytes.Buffer)
		if err := writeVarUInt(buffer, int(sff.weight)); err != nil {
			return nil, err
		}
		if smallestSet.hasIndex(i) {
			// write fulfillment
			if err := writeOctetString(buffer, sffsCachedBytes[i][0]); err != nil {
				return nil, err
			}
			// write empty condition
			if err := writeOctetString(buffer, nil); err != nil {
				return nil, err
			}
		} else {
			// write empty fulfillment
			if err := writeOctetString(buffer, nil); err != nil {
				return nil, err
			}
			// write condition
			if err := writeOctetString(buffer, sffsCachedBytes[i][1]); err != nil {
				return nil, err
			}
		}
		serializations = append(serializations, buffer.Bytes())
	}
	// sort the serializations lexicographically
	sort.Sort(serializations)

	// serialize everything
	buffer := new(bytes.Buffer)
	if err := writeVarUInt(buffer, int(ff.threshold)); err != nil {
		return nil, err
	}
	if err := writeVarUInt(buffer, len(serializations)); err != nil {
		return nil, err
	}
	for _, s := range serializations {
		if _, err := buffer.Write(s); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func (ff *FfThresholdSha256) ParsePayload(payload []byte) error {
	reader := bytes.NewReader(payload)

	var err error
	if threshold, err := readVarUInt(reader); err != nil {
		return err
	} else {
		ff.threshold = uint32(threshold)
	}
	nbFfs, err := readVarUInt(reader)
	if err != nil {
		return err
	}

	ff.subFfs = make([]*weightedSubFulfillment, nbFfs)
	for i := 0; i < nbFfs; i++ {
		weight, err := readVarUInt(reader)
		if err != nil {
			return err
		}
		ffBytes, err := readOctetString(reader)
		if err != nil {
			return err
		}
		condbytes, err := readOctetString(reader)
		if err != nil {
			return err
		}

		if len(ffBytes) > 0 && len(condbytes) > 0 {
			return errors.New("Subfulfillments may not provide both condition and fulfillment.")
		} else if len(ffBytes) > 0 {
			sff, err := DeserializeFulfillment(bytes.NewReader(ffBytes))
			if err != nil {
				return err
			}
			ff.subFfs[i] = &weightedSubFulfillment{
				weight:      uint32(weight),
				isFulfilled: true,
				ff:          sff,
			}
		} else if len(condbytes) > 0 {
			sc, err := DeserializeCondition(bytes.NewReader(condbytes))
			if err != nil {
				return err
			}
			ff.subFfs[i] = &weightedSubFulfillment{
				weight:      uint32(weight),
				isFulfilled: false,
				cond:        sc,
			}
		} else {
			return errors.New("Subconditions must provide either subcondition or fulfillment.")
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
		return errors.New("Total weight of subfulfillments is lower than threshold.")
	}

	// But the set must be minimal, there mustn't be any fulfillments we could take out
	if ff.threshold+minWeight <= totalWeight {
		return errors.New("Fulfillment is not minimal.")
	}

	// Validate all subfulfillments individually.
	for _, sff := range ff.subFfs {
		if err := sff.ff.Validate(message); err != nil {
			return err
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
	sffs := make([]*weightedFulfillmentInfo, len(ff.subFfs))
	for i, sff := range ff.subFfs {
		// size: count fulfillment length
		counter := new(writeCounter)
		if err := SerializeFulfillment(counter, sff.ff); err != nil {
			return 0, err
		}
		size := counter.Counter()
		// omit size: serialize condition
		sffCond, err := sff.ff.Condition()
		if err != nil {
			return 0, err
		}
		counter = new(writeCounter)
		if err := SerializeCondition(counter, sffCond); err != nil {
			return 0, err
		}
		omitSize := counter.Counter()

		sffs[i] = &weightedFulfillmentInfo{
			weightedSubFulfillment: sff,
			index:    i,
			size:     uint32(size),
			omitSize: uint32(omitSize),
		}
	}

	// cast to weightedFulfillmentInfoSorter so that we can sort by weight
	sorter := weightedFulfillmentInfoSorter(sffs)
	sort.Sort(sorter)

	sffsWorstLength := calculateWorstCaseSffsLength(int(ff.threshold), sffs, 0)

	if sffsWorstLength == math.MaxUint32 {
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

func calculateWorstCaseSffsLength(threshold int, sffs []*weightedFulfillmentInfo, index int) uint32 {
	if threshold <= 0 {
		// threshold reached, no additional fulfillments need to be added
		return 0
	} else if index < len(sffs) {
		// calculate whether including or excluding the fulfillment increases the size the most
		nextFf := sffs[index]
		return maxUint32(
			nextFf.size+calculateWorstCaseSffsLength(
				threshold-int(nextFf.weight),
				sffs,
				index+1,
			),
			nextFf.omitSize+calculateWorstCaseSffsLength(
				threshold,
				sffs,
				index+1,
			),
		)
	} else {
		//TODO find a better way to indicate this. pass an error object? :s
		return math.MaxUint32
	}
}

func (ff *FfThresholdSha256) getFeatures() (Features, error) {
	features := ffThresholdSha256Features
	for _, sff := range ff.subFfs {
		condition, err := sff.ff.Condition()
		if err != nil {
			return 0, err
		}
		features |= condition.Features
	}
	return features, nil
}
