# azurerm_sentinel_alert_rule_scheduled has no sub-technique argument; not applied: T1036.007, T1059.001
resource "azurerm_sentinel_alert_rule_scheduled" "eva_mdfe_01" {
  name                       = "EVA-MDFE-01"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Golden rule with 'quotes'"
  description                = "Detects things.\nSecond line with $${braces} and C:\\path."
  severity                   = "Medium"
  enabled                    = true
  query = chomp(<<KQL
DeviceProcessEvents
| where FileName endswith ".pdf.exe"
| where InitiatingProcessFileName != 'explorer.exe'
KQL
  )
  query_frequency      = "PT20M"
  query_period         = "PT1H"
  trigger_operator     = "GreaterThan"
  trigger_threshold    = 0
  suppression_enabled  = false
  suppression_duration = "PT5H"
  tactics              = ["DefenseEvasion", "InitialAccess", "Execution"]
  techniques           = ["T1036", "T1059"]

  entity_mapping {
    entity_type = "Host"

    field_mapping {
      identifier  = "FullName"
      column_name = "DeviceName"
    }
  }

  entity_mapping {
    entity_type = "Account"

    field_mapping {
      identifier  = "Name"
      column_name = "AccountName"
    }

    field_mapping {
      identifier  = "NTDomain"
      column_name = "AccountDomain"
    }
  }

  incident {
    create_incident_enabled = true

    grouping {
      enabled                = true
      lookback_duration      = "P7D"
      entity_matching_method = "AllEntities"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}
