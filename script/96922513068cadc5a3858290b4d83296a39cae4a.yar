rule WMI_strings
{
	meta:
		description = "Accesses the WMI"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		os = "windows"
		filetype = "script"

	strings:
		$a0 = /ROOT\\(CIMV2|AccessLogging|ADFS|aspnet|Cli|Hardware|interop|InventoryLogging|Microsoft.{10}|Policy|RSOP|SECURITY|ServiceModel|snmpStandardCimv2|subscription|virtualization|WebAdministration|WMI)/ nocase ascii wide

	condition:
		any of them
}
