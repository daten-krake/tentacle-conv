package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	validSeverities = []string{"Informational", "Low", "Medium", "High"}

	// isoDuration matches the subset of ISO 8601 durations Sentinel accepts for
	// query frequency/period, e.g. PT5M, PT1H, P1D, P1DT12H, P2W.
	isoDuration = regexp.MustCompile(`^P(?:\d+W|(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?)$`)

	// ruleIDPattern restricts rule IDs to characters that are safe in an ARM
	// resource name and an ARM template expression.
	ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// ValidRuleID reports whether id can be used as a Sentinel rule resource name.
func ValidRuleID(id string) bool {
	return ruleIDPattern.MatchString(id)
}

// Validate checks the fields every conversion depends on and returns all
// problems found, joined into one error. It does not modify the analytic.
func (a Analytic) Validate() error {
	var errs []error

	if strings.TrimSpace(a.Name) == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if a.ID != "" && !ValidRuleID(a.ID) {
		errs = append(errs, fmt.Errorf("id %q may only contain letters, digits, '.', '_' and '-'", a.ID))
	}
	if strings.TrimSpace(a.Query) == "" {
		errs = append(errs, errors.New("query is required"))
	}

	switch {
	case a.Severity == "":
		errs = append(errs, errors.New("severity is required"))
	case !contains(validSeverities, a.Severity):
		errs = append(errs, fmt.Errorf("severity %q must be one of %s", a.Severity, strings.Join(validSeverities, ", ")))
	}

	errs = appendDurationError(errs, "query_frequency", a.QueryFrequency)
	errs = appendDurationError(errs, "query_period", a.QueryPeriod)

	return errors.Join(errs...)
}

func appendDurationError(errs []error, field, value string) []error {
	switch {
	case value == "":
		return append(errs, fmt.Errorf("%s is required", field))
	case value == "P" || !isoDuration.MatchString(value):
		return append(errs, fmt.Errorf("%s %q is not an ISO 8601 duration (e.g. PT1H, P1D)", field, value))
	}
	return errs
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
