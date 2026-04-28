param workspace string

resource alertRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/Files_with_double_extensions'
  kind: 'Scheduled'
  properties: {
    displayName: 'Files_with_double_extensions'
    description: 'Detects double extension files'
    severity: 'Medium'
    enabled: true
    query: '''
DeviceProcessEvents
| where FileName endswith ".pdf.exe"
'''
    queryFrequency: 'PT20M'
    queryPeriod: 'PT20M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['DefenseEvasion', 'InitialAccess']
    techniques: ['T1036']
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'HostCustomEntity'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        lookbackDuration: 'P7D'
        matchingMethod: 'AllEntities'
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
  }
}
