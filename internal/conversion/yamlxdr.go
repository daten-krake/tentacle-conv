package conversion

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// xdrODataType is the type annotation of a detection rule.
const xdrODataType = "#microsoft.graph.security.detectionRule"

// SingleYAMLtoXDR reads a YAML analytic file, converts it to a Defender XDR
// custom detection rule (Graph beta detectionRules body) and writes
// <rule name>.json to outpath. Conversion warnings go to the log.
func SingleYAMLtoXDR(outpath string, file string) error {
	y, err := loadAnalytic(file)
	if err != nil {
		return err
	}

	rule, warnings, err := yamlToXDR(y)
	if err != nil {
		return fmt.Errorf("converting %s to a Defender XDR rule: %w", file, err)
	}
	for _, w := range warnings {
		log.Printf("warning: %s: %s", y.Name, w)
	}

	out, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	return writeOutput(outpath, y.Name, "json", append(out, '\n'))
}

// Frequencies Defender XDR data supports, with the lookback the service applies
// (https://learn.microsoft.com/defender-xdr/custom-detection-rules).
var xdrLookback = map[string]string{
	"PT1H":  "PT4H",
	"PT3H":  "PT12H",
	"PT12H": "PT48H",
	"P1D":   "P30D",
}

// xdrDefenderFrequencies lists the keys of xdrLookback in ascending order.
var xdrDefenderFrequencies = []string{"PT1H", "PT3H", "PT12H", "P1D"}

// Custom frequencies are only available for queries on Microsoft Sentinel data:
// 5 minutes to 14 days.
const (
	xdrMinFrequency = 5 * time.Minute
	xdrMaxFrequency = 14 * 24 * time.Hour
)

var isoDurationParts = regexp.MustCompile(`^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

// parseISODuration converts the subset of ISO 8601 durations used for query
// frequency/period (weeks, days, hours, minutes, seconds) to a time.Duration.
func parseISODuration(s string) (time.Duration, error) {
	m := isoDurationParts.FindStringSubmatch(s)
	if m == nil || s == "P" || strings.HasSuffix(s, "T") {
		return 0, fmt.Errorf("%q is not an ISO 8601 duration", s)
	}
	unit := []time.Duration{7 * 24 * time.Hour, 24 * time.Hour, time.Hour, time.Minute, time.Second}
	var d time.Duration
	for i, u := range unit {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return 0, err
		}
		d += time.Duration(n) * u
	}
	return d, nil
}

// xdrEntities translates Sentinel entity types and identifiers to the typed
// mapping objects of the Graph entityMappingConfiguration. Identifiers not
// listed have no XDR counterpart and are reported.
var xdrEntities = map[string]struct {
	collection  string
	identifiers map[string]string
}{
	"Account": {"accounts", map[string]string{
		"Name": "nameColumn", "NTDomain": "ntDomainColumn", "DnsDomain": "dnsDomainColumn",
		"UPNSuffix": "upnSuffixColumn", "Sid": "sidColumn", "AadUserId": "aadUserIdColumn",
	}},
	"Host": {"hosts", map[string]string{
		"HostName": "nameColumn", "DnsDomain": "dnsDomainColumn", "NTDomain": "ntDomainColumn",
		"NetBiosName": "netBiosNameColumn", "MdatpDeviceId": "deviceIdColumn",
	}},
	"IP":   {"ips", map[string]string{"Address": "addressColumn", "AddressScope": "scopeColumn"}},
	"URL":  {"urls", map[string]string{"Url": "addressColumn"}},
	"File": {"files", map[string]string{"Name": "nameColumn"}},
	// processEntityMapping only has sha1Column/sha256Column, which no Sentinel
	// Process identifier supplies, so every Process identifier is reported.
	"Process":          {"processes", map[string]string{}},
	"DNS":              {"dns", map[string]string{"DomainName": "domainNameColumn"}},
	"Mailbox":          {"mailboxes", map[string]string{"MailboxPrimaryAddress": "primaryAddressColumn"}},
	"MailCluster":      {"mailClusters", map[string]string{"Query": "queryColumn", "Source": "sourceColumn"}},
	"CloudApplication": {"cloudApplications", map[string]string{"AppId": "appIdColumn", "Name": "nameColumn"}},
	"AzureResource":    {"azureResources", map[string]string{"ResourceId": "resourceIdColumn"}},
	"RegistryValue":    {"registryValues", map[string]string{"Name": "valueNameColumn"}},
	"MailMessage": {"mailMessages", map[string]string{
		"NetworkMessageId": "networkMessageIdColumn", "Recipient": "recipientColumn",
		"Sender": "senderColumn", "Subject": "subjectColumn",
	}},
	"SecurityGroup": {"securityGroups", map[string]string{
		"DistinguishedName": "distinguishedNameColumn", "SID": "sidColumn", "ObjectGuid": "objectIdColumn",
	}},
}

// Backward-compatible Sentinel identifiers that are not part of the entity
// schema. They are translated with a warning.
const (
	legacyFullName    = "FullName"
	legacyDisplayName = "DisplayName"
)

var upnLike = regexp.MustCompile(`(?i)upn|userprincipalname`)

// buildXDREntityMappings translates the prodyaml entity_mapping. Each entry
// becomes one XDR mapping object, so two IP entries (source, destination)
// stay two entities.
func buildXDREntityMappings(input []model.Entities) (model.EntityMappingConfiguration, []string) {
	var warnings []string
	result := model.EntityMappingConfiguration{}
	perCollection := map[string]int{}

	for i, em := range input {
		spec, known := xdrEntities[em.EntityType]
		if !known {
			warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: entity type %q has no Defender XDR equivalent and is skipped", i, em.EntityType))
			continue
		}

		obj := map[string]string{}
		for _, fm := range em.FieldMapping {
			prop, ok := spec.identifiers[fm.Identifier]
			switch {
			case ok:
			case fm.Identifier == legacyFullName && em.EntityType == "Account":
				// FullName is a legacy identifier. A UPN-shaped column goes to
				// upnColumn, anything else to nameColumn.
				prop = "nameColumn"
				if upnLike.MatchString(fm.ColumnName) {
					prop = "upnColumn"
				}
				warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: legacy identifier %s of Account is mapped to %s; review", i, fm.Identifier, prop))
			case (fm.Identifier == legacyFullName || fm.Identifier == legacyDisplayName) && em.EntityType == "Host":
				prop = "nameColumn"
				warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: legacy identifier %s of Host is mapped to nameColumn; review", i, fm.Identifier))
			case fm.Identifier == legacyDisplayName && em.EntityType == "Account":
				prop = "nameColumn"
				warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: legacy identifier DisplayName of Account is mapped to nameColumn; review", i))
			default:
				warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: identifier %s of %s has no Defender XDR column and is skipped", i, fm.Identifier, em.EntityType))
				continue
			}
			if prev, dup := obj[prop]; dup && prev != fm.ColumnName {
				warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: %s is mapped twice (%q, %q); keeping the first", i, prop, prev, fm.ColumnName))
				continue
			}
			obj[prop] = fm.ColumnName
		}

		if len(obj) == 0 {
			warnings = append(warnings, fmt.Sprintf("entity_mapping[%d]: no identifier of %s could be mapped; the entity is skipped", i, em.EntityType))
			continue
		}
		result[spec.collection] = append(result[spec.collection], obj)
		perCollection[spec.collection]++
	}

	for _, c := range []string{"accounts", "hosts", "mailboxes"} {
		if perCollection[c] > 1 {
			warnings = append(warnings, fmt.Sprintf("%d %s mappings: the Defender portal documents a single column per impacted-asset type", perCollection[c], c))
		}
	}
	if len(result) == 0 {
		return nil, warnings
	}
	return result, warnings
}

// buildXDRTactics nests each prodyaml mitre entry's techniques under every
// tactic of that entry. prodyaml does not record which technique belongs to
// which tactic, so an entry's techniques are attached to all of its tactics.
func buildXDRTactics(mitre []model.Mitre) []model.MitreTactic {
	var out []model.MitreTactic
	index := map[string]int{}

	for _, m := range mitre {
		// Parent technique -> sub-techniques, in first-seen order.
		var order []string
		subs := map[string][]string{}
		for _, t := range m.Techniques {
			parent, _, isSub := strings.Cut(t, ".")
			if _, seen := subs[parent]; !seen {
				order = append(order, parent)
				subs[parent] = nil
			}
			if isSub {
				subs[parent] = appendUnique(subs[parent], t)
			}
		}

		for _, tactic := range m.Tactics {
			i, ok := index[tactic]
			if !ok {
				i = len(out)
				index[tactic] = i
				out = append(out, model.MitreTactic{Tactic: tactic})
			}
			for _, parent := range order {
				out[i].Techniques = mergeXDRTechnique(out[i].Techniques, parent, subs[parent])
			}
		}
	}
	return out
}

func mergeXDRTechnique(list []model.MitreTechnique, parent string, subs []string) []model.MitreTechnique {
	for i := range list {
		if list[i].Technique == parent {
			for _, s := range subs {
				list[i].SubTechniques = appendUnique(list[i].SubTechniques, s)
			}
			return list
		}
	}
	return append(list, model.MitreTechnique{Technique: parent, SubTechniques: append([]string(nil), subs...)})
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// xdrRuleID returns the client-provided rule id: the prodyaml id, or a slug of
// the name.
func xdrRuleID(a model.Analytic) string {
	if a.ID != "" {
		return a.ID
	}
	return strings.Trim(nonSlugChars.ReplaceAllString(strings.ToLower(a.Name), "-"), "-")
}

var (
	htmlTag     = regexp.MustCompile(`<[A-Za-z/][^>]*>`)
	timeFilter  = regexp.MustCompile(`(?i)\b(Timestamp|TimeGenerated)\b\s*(>=|>|<=|<)\s*ago\s*\(`)
	reportIDCol = regexp.MustCompile(`\bReportId\b`)
)

// yamlToXDR maps a prodyaml Analytic to a Defender XDR detection rule. It
// returns warnings for everything that is dropped or approximated and an error
// when the rule cannot be expressed at all.
func yamlToXDR(a model.Analytic) (model.DetectionRule, []string, error) {
	var warnings []string

	id := xdrRuleID(a)
	if id == "" {
		return model.DetectionRule{}, nil, fmt.Errorf("cannot derive a rule id from name %q; set id", a.Name)
	}

	freq, err := parseISODuration(a.QueryFrequency)
	if err != nil {
		return model.DetectionRule{}, nil, fmt.Errorf("query_frequency: %w", err)
	}
	if freq < xdrMinFrequency || freq > xdrMaxFrequency {
		return model.DetectionRule{}, nil, fmt.Errorf("query_frequency %s is outside the 5 minutes to 14 days Defender XDR supports", a.QueryFrequency)
	}
	if lookback, fixed := xdrLookback[a.QueryFrequency]; fixed {
		if a.QueryPeriod != lookback {
			warnings = append(warnings, fmt.Sprintf("query_period %s is not sent to XDR; for Defender data the lookback is fixed at %s for frequency %s", a.QueryPeriod, lookback, a.QueryFrequency))
		}
	} else {
		warnings = append(warnings, fmt.Sprintf("query_frequency %s is a custom frequency, which XDR accepts only for queries on Microsoft Sentinel data (Defender data: %s)", a.QueryFrequency, strings.Join(xdrDefenderFrequencies, ", ")))
	}

	status := "disabled"
	if strings.EqualFold(a.State, "prod") {
		status = "enabled"
	} else {
		warnings = append(warnings, fmt.Sprintf("state %q is not \"prod\": the rule is written as disabled", a.State))
	}

	if htmlTag.MatchString(a.Description) {
		warnings = append(warnings, "description contains HTML; Defender XDR removes HTML and Markdown from descriptions")
	}
	if !reportIDCol.MatchString(a.Query) {
		warnings = append(warnings, "query does not mention ReportId; Defender recommends projecting Timestamp and ReportId (plus DeviceId for MDE tables)")
	}
	if timeFilter.MatchString(a.Query) {
		warnings = append(warnings, "query filters Timestamp/TimeGenerated with ago(); the service pre-filters by the lookback, so this filter is usually unnecessary")
	}

	mappings, w := buildXDREntityMappings(a.EntityMapping)
	warnings = append(warnings, w...)

	rule := model.DetectionRule{
		ODataType:      xdrODataType,
		ID:             id,
		DisplayName:    a.Name,
		Description:    a.Description,
		Status:         status,
		QueryCondition: model.QueryCondition{QueryText: a.Query},
		Schedule:       model.RuleSchedule{Frequency: a.QueryFrequency},
		DetectionAction: model.DetectionAction{
			AlertTemplate: model.AlertTemplate{
				Title:              a.Name,
				Description:        a.Description,
				Severity:           strings.ToLower(a.Severity),
				RecommendedActions: a.ResponsePlan,
				EntityMappings:     mappings,
				Tactics:            buildXDRTactics(a.Mitre),
			},
			IncidentConfiguration: model.XDRIncidentConfiguration{IsExcludedFromIncidentCorrelation: false},
		},
	}
	return rule, warnings, nil
}
