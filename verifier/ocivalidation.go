// Copyright (c) 2025 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verifier

import (
	"fmt"
	"reflect"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func ConvertSpec(s ar.Serializer, spec *specs.Spec) (map[string]interface{}, error) {

	data, err := s.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	conv := make(map[string]interface{})
	err = s.Unmarshal(data, &conv)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config to map: %w", err)
	}

	return conv, nil
}

func ValidateConfig(reference, measurement, rules map[string]interface{}) error {

	log.Tracef("Running recursive config validation..")

	// Ensure all fields in the reference config have a corresponding measurement value
	// according to the rules defined in the rules config
	for key, refValue := range reference {

		// Get rules and measurement property for reference property
		rule, ruleExists := rules[key]
		measureValue, measurementExists := measurement[key]

		if !ruleExists {
			// If no rule is defined, treat the value as mandatory, i.e., enforce exact match
			log.Tracef(" No rule defined for field %q", key)
			if !reflect.DeepEqual(refValue, measureValue) {
				switch measureValue.(type) {
				case string, int, bool:
					log.Tracef(" Field %q does not reference: %v vs %v", key, measureValue, refValue)
				default:
					log.Tracef(" Field %q does not reference", key)
				}
				return fmt.Errorf(" field %q is implicitly mandatory and does not match reference", key)
			} else {
				switch measureValue.(type) {
				case string, int, bool:
					log.Tracef(" Field %q matches reference: %v", key, measureValue)
				default:
					log.Tracef(" Field %q matches reference", key)
				}
			}
		} else {

			// Else validate based on the rule
			switch ruleType := rule.(type) {
			case string: // Rule specifies a JSON scalar or array of scalars

				log.Debugf(" Rule %v defined for scalar field %q", rule, key)

				if strings.HasPrefix(ruleType, "replace:") {
					err := applyReplace(ruleType, key, refValue, measureValue)
					if err != nil {
						return err
					}
					continue
				}

				if rule != "mandatory" && rule != "optional" && rule != "modifiable" && rule != "subset" {
					return fmt.Errorf(" unsupported rule type: %v", rule)
				}

				if reflect.DeepEqual(refValue, measureValue) {
					log.Tracef(" Field %q is %v and matches reference", key, rule)
					continue
				}
				if ruleType == "optional" {
					if !measurementExists {
						log.Tracef(" Field %q is optional and missing in target config", key)
						continue
					} else {
						return fmt.Errorf(" field %q is optional, present, and has different value %v (vs. %v)",
							key, measureValue, refValue)
					}
				} else if ruleType == "modifiable" {
					log.Tracef(" Field %q is %v and was modified (%v to %v)",
						key, rule, refValue, measureValue)
					continue
				} else if ruleType == "subset" {
					refArr, refOk := refValue.([]interface{})
					measurementArr, measurementOk := measureValue.([]interface{})
					if !refOk || !measurementOk {
						return fmt.Errorf(" fields %q must be JSON array type: ref: %T, meas: %T",
							key, refValue, measureValue)
					}
					if isSubset(measurementArr, refArr) {
						log.Tracef(" Field %q is subset of reference", key)
						continue
					} else {
						return fmt.Errorf(" field %q is not a subset (%v vs. %v)",
							key, refValue, measureValue)
					}
				}

			case []interface{}: // Rule specifies a JSON array of nested objects
				log.Debugf(" Rules defined for array %v", key)

				refArr, refOk := refValue.([]interface{})
				measurementArr, measurementOk := measureValue.([]interface{})
				if !refOk || !measurementOk {
					return fmt.Errorf(" nested array field %q must be a JSON object: ref: %v, meas: %v",
						key, refOk, measurementOk)
				}
				if len(ruleType) > len(refArr) || len(ruleType) > len(measurementArr) {
					return fmt.Errorf(" field %q has %v elements, but rule has %v elements",
						key, len(refArr), len(ruleType))
				}
				if len(measurementArr) != len(refArr) {
					return fmt.Errorf(" field %q has %v elements, but reference has %v elements",
						key, len(measurementArr), len(refArr))
				}

				for i := range refArr {

					if i >= len(ruleType) {
						log.Tracef(" No rule defined for array element %v: %v, implicit mandatory",
							key, i)
						if reflect.DeepEqual(refArr[i], measurementArr[i]) {
							log.Tracef(" Array element %v matches reference", i)
							continue
						} else {
							return fmt.Errorf(" array element %v must match reference (%v vs. %v)",
								i, measurementArr[i], refArr[i])
						}
					}

					switch innerRuleType := ruleType[i].(type) {
					case map[string]interface{}:
						refElem, ok := refArr[i].(map[string]interface{})
						if !ok {
							return fmt.Errorf(" nested ref array field elements in %q must be JSON objects",
								key)
						}
						measElem, ok := measurementArr[i].(map[string]interface{})
						if !ok {
							return fmt.Errorf(" nested array field elements in %v must be JSON objects",
								key)
						}
						err := ValidateConfig(refElem, measElem, innerRuleType)
						if err != nil {
							return fmt.Errorf("failed to validate config: %w", err)
						}
					default:
						log.Errorf(" unknown ruletype: %v", innerRuleType)
					}
				}
				continue

			case map[string]interface{}: // Rule specifies a nested JSON object
				log.Debugf(" Rules defined for nested object %v", key)
				refMap, refOk := refValue.(map[string]interface{})
				measurementMap, measurementOk := measureValue.(map[string]interface{})
				if !refOk || !measurementOk {
					return fmt.Errorf(" nested field %q must be a JSON object", key)
				}
				err := ValidateConfig(refMap, measurementMap, ruleType)
				if err != nil {
					return fmt.Errorf("failed to validate config: %w", err)
				}
				continue

			default:
				log.Warnf(" Unsupported rule type: %v", ruleType)

			}

			return fmt.Errorf(" field %q is %v and does not match reference (%v vs. %v)",
				key, rule, measureValue, refValue)
		}
	}

	// Ensure all fields in the measurement config are in the reference config or marked as additional
	for key := range measurement {
		// If the measurement key exists in the reference, it has already been validated
		err := checkAdditionalKey(key, reference, measurement, rules)
		if err != nil {
			return fmt.Errorf(" %w", err)
		}
	}

	log.Tracef("Returning from recursive validation")

	return nil
}

func checkAdditionalKey(key string, reference, measurement, rules map[string]interface{}) error {
	if _, exists := reference[key]; !exists {
		// If it does not exist, there must be an additional rule defined for the key
		rule, ruleExists := rules[key]
		if !ruleExists {
			return fmt.Errorf("unexpected field %q found in measurement config", key)
		}
		switch ruleType := rule.(type) {
		case string:
			// Check if an "additional" rule was defined
			ruleParts := strings.SplitN(ruleType, ":", 2)
			if ruleParts[0] != "additional" {
				return fmt.Errorf("measurement-only key %v is not defined as additional (%v)", key, ruleType)
			}
			// Check if specific additional values have been specified
			if len(ruleParts) == 2 {
				if ruleParts[1] != measurement[key] {
					return fmt.Errorf("additional measurement-only key %v does not have value %v (%v)",
						key, measurement[key], ruleParts[1])
				}
				log.Tracef("Allow additional measurement-only key %v with specific value %v", key, ruleParts[1])
			} else {
				log.Tracef("Allow additional measurement-only key %v with arbitrary value", key)
			}
		default:
			return fmt.Errorf("unsupported rule type for measurement-only key %v: %v", key, ruleType)
		}
	}
	return nil
}

// applyReplace handles the "replace:KEY=*[,KEY=*]" rule for string arrays.
// It replaces measurement entries matching wildcard keys with their reference
// counterparts, then compares for equality.
func applyReplace(rule, field string, refValue, measureValue interface{}) error {
	patterns := strings.TrimPrefix(rule, "replace:")
	wildcardKeys := make(map[string]bool)
	for _, pattern := range strings.Split(patterns, ",") {
		key, _, ok := strings.Cut(pattern, "=")
		if !ok || key == "" {
			return fmt.Errorf(" invalid replace pattern %q for field %q", pattern, field)
		}
		wildcardKeys[key] = true
	}

	refArr, refOk := refValue.([]interface{})
	measArr, measOk := measureValue.([]interface{})
	if !refOk || !measOk {
		return fmt.Errorf(" field %q must be a JSON array for replace rule: ref: %T, meas: %T",
			field, refValue, measureValue)
	}

	// Build key:entry map from reference array
	refByKey := make(map[string]interface{})
	for _, entry := range refArr {
		s, ok := entry.(string)
		if !ok {
			continue
		}
		key, _, _ := strings.Cut(s, "=")
		refByKey[key] = entry
	}

	// Replace wildcard entries in measurement with reference values
	replaced := make([]interface{}, len(measArr))
	copy(replaced, measArr)
	for i, entry := range replaced {
		s, ok := entry.(string)
		if !ok {
			continue
		}
		key, _, _ := strings.Cut(s, "=")
		if wildcardKeys[key] {
			if refEntry, exists := refByKey[key]; exists {
				log.Tracef(" Replacing measurement entry %q with reference value for key %q", s, key)
				replaced[i] = refEntry
			}
		}
	}

	if !reflect.DeepEqual(refArr, replaced) {
		return fmt.Errorf(" field %q does not match reference after applying replace rule", field)
	}

	log.Tracef(" Field %q matches reference after replace rule", field)
	return nil
}

// isSubset checks if a slice is a subset of another slice
func isSubset(subset, superset []interface{}) bool {
	for _, subElem := range subset {
		found := false
		for _, superElem := range superset {
			if reflect.DeepEqual(subElem, superElem) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
