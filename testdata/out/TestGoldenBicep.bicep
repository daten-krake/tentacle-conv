param workspace string

resource alertRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/EVA-MDFE-01'
  kind: 'Scheduled'
  properties: {
    displayName: 'Golden rule with \'quotes\''
    description: 'Detects things.\nSecond line with \${braces} and C:\\path.'
    severity: 'Medium'
    enabled: true
    query: 'DeviceProcessEvents\n| where FileName endswith ".pdf.exe"\n| where InitiatingProcessFileName != \'explorer.exe\''
    queryFrequency: 'PT20M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['DefenseEvasion', 'InitialAccess', 'Execution']
    techniques: ['T1036', 'T1059']
    subTechniques: ['T1036.007', 'T1059.001']
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'DeviceName'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
          {
            identifier: 'NTDomain'
            columnName: 'AccountDomain'
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
