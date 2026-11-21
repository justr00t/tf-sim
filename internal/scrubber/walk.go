package scrubber

import (
	"encoding/json"
	"fmt"

	"github.com/justr00t/tf-sim/internal/model"
)

const maxRecursionDepth = 512

func scrubStateValue(val any, mask any, customRedactKeys map[string]struct{}, summary *model.ScrubSummary) (any, error) {
	if val == nil {
		return nil, nil
	}
	return walkValue(val, mask, false, false, 0, customRedactKeys, summary)
}

func walkValue(
	val any,
	mask any,
	forceMask bool,
	forceKey bool,
	depth int,
	customRedactKeys map[string]struct{},
	summary *model.ScrubSummary,
) (any, error) {
	if depth > maxRecursionDepth {
		return nil, fmt.Errorf("maximum JSON nesting depth (%d) exceeded", maxRecursionDepth)
	}

	if b, ok := mask.(bool); ok && b {
		forceMask = true
	}

	switch v := val.(type) {
	case nil:
		return nil, nil

	case map[string]any:
		maskMap, _ := mask.(map[string]any)
		out := make(map[string]any, len(v))
		for k, childVal := range v {
			var childMask any
			if maskMap != nil {
				childMask = maskMap[k]
			}
			_, isCustom := customRedactKeys[normalizeKey(k)]
			childForceMask := forceMask || isCustom
			childForceKey := forceKey || (!childForceMask && isBuiltinSensitiveKey(k))

			scrubbedChild, err := walkValue(childVal, childMask, childForceMask, childForceKey, depth+1, customRedactKeys, summary)
			if err != nil {
				return nil, err
			}
			out[k] = scrubbedChild
		}
		return out, nil

	case []any:
		maskSlice, _ := mask.([]any)
		out := make([]any, len(v))
		for i, elem := range v {
			var elemMask any
			if i < len(maskSlice) {
				elemMask = maskSlice[i]
			}
			scrubbedElem, err := walkValue(elem, elemMask, forceMask, forceKey, depth+1, customRedactKeys, summary)
			if err != nil {
				return nil, err
			}
			out[i] = scrubbedElem
		}
		return out, nil

	case string:
		if v == RedactedPlaceholder {
			return RedactedPlaceholder, nil
		}
		if forceMask {
			summary.RedactedByMaskCount++
			return RedactedPlaceholder, nil
		}
		if forceKey {
			summary.RedactedByKeyCount++
			return RedactedPlaceholder, nil
		}
		if isSecretStringValue(v) {
			summary.RedactedByValueCount++
			return RedactedPlaceholder, nil
		}
		return v, nil

	case json.Number, float64, int, int64:
		if forceMask {
			summary.RedactedByMaskCount++
			return RedactedPlaceholder, nil
		}
		if forceKey {
			summary.RedactedByKeyCount++
			return RedactedPlaceholder, nil
		}
		return v, nil

	case bool:
		if forceMask {
			summary.RedactedByMaskCount++
			return RedactedPlaceholder, nil
		}
		return v, nil

	default:
		if forceMask || forceKey {
			summary.RedactedByMaskCount++
			return RedactedPlaceholder, nil
		}
		return v, nil
	}
}
