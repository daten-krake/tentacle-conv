param workspace string

resource alertRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/c0a90f5f-389e-5747-89ee-bc47e5abe17b'
  kind: 'Scheduled'
  properties: {
    displayName: 'Files_with_double_extensions'
    description: 'Detects double extension files'
    severity: 'Medium'
    enabled: true
    query: '''
DeviceProcessEvents
| where FileName endswith ".pdf.exe"'''
    queryFrequency: 'PT20M'
    queryPeriod: 'PT20M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['DefenseEvasion', 'InitialAccess']
    techniques: ['T1036']
    subTechniques: []
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
