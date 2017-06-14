package cryptoconditions

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/kalaspuffar/base64url"
	"github.com/pkg/errors"
)

// generateURI generates a URI for the given condition.
func generateURI(condition Condition) string {
	params := make(url.Values)
	params.Set("fpt", strings.ToLower(conditionTypeNames[condition.Type()]))
	params.Set("cost", fmt.Sprintf("%d", condition.Cost()))

	if compound, ok := condition.(*compoundCondition); ok {
		subtypeStrings := make([]string, 0, nbKnownConditionTypes)
		subtypes := compound.SubTypes()
		for st, stStr := range conditionTypeNames {
			if subtypes.Has(st) {
				subtypeStrings = append(subtypeStrings,
					strings.ToLower(stStr))
			}
		}
		if len(subtypeStrings) != 0 {
			params.Set("subtypes", strings.Join(subtypeStrings, ","))
		}
	}

	encodedFingerprint := base64url.Encode(condition.Fingerprint())
	uri := url.URL{
		Scheme:   "ni",
		Path:     "/sha-256;" + encodedFingerprint,
		RawQuery: params.Encode(),
	}

	return uri.String()
}

// ParseURI parses a URI into a Condition.
func ParseURI(uri string) (Condition, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse URI")
	}
	params := u.Query()

	// Find the condition type.
	conditionTypeString := strings.ToUpper(params.Get("fpt"))
	conditionType, found := conditionTypeDictionary[conditionTypeString]
	if !found {
		return nil, errors.Errorf(
			"unknown condition type: %s", params.Get("fpt"))
	}

	// Parse the fingerprint.
	pathParts := strings.SplitN(u.Path, ";", 1)
	if len(pathParts) != 2 {
		return nil, errors.New("incorrectly formatted URI, no semicolon found")
	}
	fingerprint, err := base64url.Decode(pathParts[1])
	if err != nil {
		return nil, errors.Wrap(err,
			"failed to decode base64url encoded fingerprint")
	}

	// Parse cost.
	parsedInt, err := strconv.ParseInt(params.Get("cost"), 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err,
			"failed to parse cost value %s", params.Get("cost"))
	}
	cost := int(parsedInt)

	switch conditionTypeMap[conditionType] {

	case simpleConditionType:
		return NewSimpleCondition(conditionType, fingerprint, cost), nil

	case compoundConditionType:
		// Parse subtypes.
		var subtypeSet ConditionTypeSet
		subtypeStrings := strings.Split(params.Get("subtypes"), ",")
		for _, subtypeString := range subtypeStrings {
			subType, found := conditionTypeDictionary[strings.ToLower(subtypeString)]
			if !found {
				return nil, errors.Errorf(
					"unknown condition type in subconditions: %s",
					subtypeString)
			}
			subtypeSet.Add(subType)
		}
		return NewCompoundCondition(
			conditionType, fingerprint, cost, subtypeSet), nil

	default:
		return nil, errors.Errorf(
			"unexpected error generating condition of type %s",
			conditionTypeString)
	}
}
