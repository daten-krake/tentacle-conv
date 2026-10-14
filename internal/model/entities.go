package model

import (
	"fmt"
	"sort"
	"strings"
)

// Limits of a Sentinel analytics rule (and of azurerm's entity_mapping).
const (
	MaxEntityMappings = 10
	MaxFieldMappings  = 3
)

// EntitySpec describes one Sentinel entity type usable in an entity mapping,
// from https://learn.microsoft.com/azure/sentinel/entities-reference.
type EntitySpec struct {
	// Identifiers that can be used in a mapping of this type.
	Identifiers []string
	// Legacy identifiers are accepted for backward compatibility only; the
	// documentation says they are not part of the entity schema.
	Legacy []string
	// Strong lists the combinations of mappable identifiers that identify an
	// entity on their own. Any one satisfied combination is enough.
	Strong [][]string
	// NeedsInternal is set when a strong identification also needs an internal
	// entity (e.g. the Host of a Process) that cannot be mapped directly.
	NeedsInternal bool
}

// SentinelEntities is the entity vocabulary prodyaml's entity_type and
// identifier values are checked against.
//
// MdatpDeviceId is not in the documentation's table, but is used for Host
// mappings in the wild and is accepted as an extension.
var SentinelEntities = map[string]EntitySpec{
	"Account": {
		Identifiers: []string{"Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid", "AadTenantId", "AadUserId", "PUID", "IsDomainJoined", "DisplayName", "ObjectGuid"},
		Legacy:      []string{"FullName", "DisplayName"},
		Strong:      [][]string{{"Name", "UPNSuffix"}, {"AadUserId"}, {"Sid"}, {"Name", "NTDomain"}, {"Name", "DnsDomain"}, {"PUID"}, {"ObjectGuid"}},
	},
	"Host": {
		Identifiers: []string{"DnsDomain", "NTDomain", "HostName", "FullName", "NetBiosName", "AzureID", "OMSAgentID", "OSFamily", "OSVersion", "IsDomainJoined", "MdatpDeviceId"},
		Legacy:      []string{"FullName"},
		Strong: [][]string{
			{"HostName", "NTDomain"}, {"HostName", "DnsDomain"}, {"NetBiosName", "NTDomain"}, {"NetBiosName", "DnsDomain"},
			{"AzureID"}, {"OMSAgentID"}, {"MdatpDeviceId"},
		},
	},
	"IP":               {Identifiers: []string{"Address", "AddressScope"}, Strong: [][]string{{"Address"}}},
	"URL":              {Identifiers: []string{"Url"}, Strong: [][]string{{"Url"}}},
	"AzureResource":    {Identifiers: []string{"ResourceId"}, Strong: [][]string{{"ResourceId"}}},
	"CloudApplication": {Identifiers: []string{"AppId", "Name", "InstanceName"}, Strong: [][]string{{"AppId"}, {"Name"}}},
	"DNS":              {Identifiers: []string{"DomainName"}, NeedsInternal: true},
	"File":             {Identifiers: []string{"Directory", "Name"}, Strong: [][]string{{"Directory", "Name"}}},
	"FileHash":         {Identifiers: []string{"Algorithm", "Value"}, Strong: [][]string{{"Algorithm", "Value"}}},
	"Malware":          {Identifiers: []string{"Name", "Category"}, Strong: [][]string{{"Name", "Category"}}},
	"Process":          {Identifiers: []string{"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"}, NeedsInternal: true},
	"RegistryKey":      {Identifiers: []string{"Hive", "Key"}, Strong: [][]string{{"Hive", "Key"}}},
	"RegistryValue":    {Identifiers: []string{"Name", "Value", "ValueType"}, NeedsInternal: true},
	"SecurityGroup":    {Identifiers: []string{"DistinguishedName", "SID", "ObjectGuid"}, Strong: [][]string{{"DistinguishedName"}, {"SID"}, {"ObjectGuid"}}},
	"Mailbox": {
		Identifiers: []string{"MailboxPrimaryAddress", "DisplayName", "Upn", "ExternalDirectoryObjectId", "RiskLevel"},
		Strong:      [][]string{{"MailboxPrimaryAddress"}},
	},
	"MailCluster": {
		Identifiers: []string{"NetworkMessageIds", "CountByDeliveryStatus", "CountByThreatType", "CountByProtectionStatus", "Threats", "Query", "QueryTime", "MailCount", "IsVolumeAnomaly", "Source", "ClusterSourceIdentifier", "ClusterSourceType", "ClusterQueryStartTime", "ClusterQueryEndTime", "ClusterGroup"},
		Strong:      [][]string{{"Query", "Source"}},
	},
	"MailMessage": {
		Identifiers: []string{
			"Recipient", "Urls", "Threats", "Sender", "P1Sender", "P1SenderDisplayName", "P1SenderDomain", "SenderIP",
			"P2Sender", "P2SenderDisplayName", "P2SenderDomain", "ReceivedDate", "NetworkMessageId", "InternetMessageId",
			"Subject", "BodyFingerprintBin1", "BodyFingerprintBin2", "BodyFingerprintBin3", "BodyFingerprintBin4",
			"BodyFingerprintBin5", "AntispamDirection", "DeliveryAction", "DeliveryLocation", "Language", "ThreatDetectionMethods",
		},
		Strong: [][]string{{"NetworkMessageId", "Recipient"}},
	},
	// A strong SubmissionMail needs four identifiers, but a mapping takes at
	// most three, so it can only ever be weak.
	"SubmissionMail": {
		Identifiers: []string{"NetworkMessageId", "Timestamp", "Recipient", "Sender", "SenderIp", "Subject", "ReportType", "SubmissionId", "SubmissionDate", "Submitter"},
	},
}

// EntityTypeNames returns the supported entity types in sorted order.
func EntityTypeNames() []string {
	names := make([]string, 0, len(SentinelEntities))
	for n := range SentinelEntities {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// HasIdentifier reports whether id is a valid identifier of the entity type.
func (s EntitySpec) HasIdentifier(id string) bool {
	return contains(s.Identifiers, id)
}

// IsLegacy reports whether id is a backward-compatibility-only identifier.
func (s EntitySpec) IsLegacy(id string) bool {
	return contains(s.Legacy, id)
}

// IsStrong reports whether the given identifiers contain a combination that
// identifies the entity on its own.
func (s EntitySpec) IsStrong(ids []string) bool {
	for _, combo := range s.Strong {
		ok := true
		for _, c := range combo {
			if !contains(ids, c) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// EntityIssue is a violation of a hard limit of entity mapping. Index is the
// position in entity_mapping, or -1 for a problem of the list itself.
type EntityIssue struct {
	Index   int
	Message string
}

// EntityMappingIssues returns every hard-limit violation of the rule's
// entity_mapping. A rule with issues cannot be deployed.
func (a Analytic) EntityMappingIssues() []EntityIssue {
	var issues []EntityIssue

	if n := len(a.EntityMapping); n > MaxEntityMappings {
		issues = append(issues, EntityIssue{-1, fmt.Sprintf("%d entity mappings; a rule allows at most %d", n, MaxEntityMappings)})
	}

	for i, em := range a.EntityMapping {
		spec, known := SentinelEntities[em.EntityType]
		if !known {
			hint := ""
			for _, name := range EntityTypeNames() {
				if strings.EqualFold(name, em.EntityType) {
					hint = fmt.Sprintf(" (did you mean %q?)", name)
					break
				}
			}
			issues = append(issues, EntityIssue{i, fmt.Sprintf("unknown entity_type %q%s; valid types: %s", em.EntityType, hint, strings.Join(EntityTypeNames(), ", "))})
		}

		switch n := len(em.FieldMapping); {
		case n == 0:
			issues = append(issues, EntityIssue{i, "no field_mapping; at least one identifier is required"})
		case n > MaxFieldMappings:
			issues = append(issues, EntityIssue{i, fmt.Sprintf("%d field_mapping entries; at most %d identifiers are allowed per entity", n, MaxFieldMappings)})
		}

		seen := map[string]bool{}
		for j, fm := range em.FieldMapping {
			if strings.TrimSpace(fm.ColumnName) == "" {
				issues = append(issues, EntityIssue{i, fmt.Sprintf("field_mapping[%d] (%s): empty column_name", j, fm.Identifier)})
			}
			if seen[fm.Identifier] {
				issues = append(issues, EntityIssue{i, fmt.Sprintf("identifier %q is mapped more than once", fm.Identifier)})
			}
			seen[fm.Identifier] = true
			if known && !spec.HasIdentifier(fm.Identifier) {
				issues = append(issues, EntityIssue{i, fmt.Sprintf("identifier %q is not valid for %s; valid identifiers: %s", fm.Identifier, em.EntityType, strings.Join(spec.Identifiers, ", "))})
			}
		}
	}
	return issues
}
