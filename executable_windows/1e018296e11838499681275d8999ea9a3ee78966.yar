import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_SQLQuery_ConfidentialDataStore
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
		os = "windows"
		filetype = "executable"

	strings:
		$select = "select " ascii wide nocase
		$table1 = " from credit_cards" ascii wide nocase
		$table2 = " from logins" ascii wide nocase
		$table3 = " from cookies" ascii wide nocase
		$table4 = " from moz_cookies" ascii wide nocase
		$table5 = " from moz_formhistory" ascii wide nocase
		$table6 = " from moz_logins" ascii wide nocase
		$column1 = "name" ascii wide nocase
		$column2 = "password_value" ascii wide nocase
		$column3 = "encrypted_value" ascii wide nocase
		$column4 = "card_number_encrypted" ascii wide nocase
		$column5 = "isHttpOnly" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}
