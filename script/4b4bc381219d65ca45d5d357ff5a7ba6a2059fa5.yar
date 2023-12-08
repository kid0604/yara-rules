rule Windows_Exploit_Log4j_dbac7698
{
	meta:
		author = "Elastic Security"
		id = "dbac7698-906c-44a2-9795-f04ec07d7fcc"
		fingerprint = "cd06db6f5bebf0412d056017259b5451184d5ba5b2976efd18fa8f96dba6a159"
		creation_date = "2021-12-13"
		last_modified = "2022-01-13"
		threat_name = "Windows.Exploit.Log4j"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows exploit related to Log4j vulnerability"
		filetype = "script"

	strings:
		$jndi1 = "jndi.ldap.LdapCtx.c_lookup"
		$jndi2 = "logging.log4j.core.lookup.JndiLookup.lookup"
		$jndi3 = "com.sun.jndi.url.ldap.ldapURLContext.lookup"
		$exp1 = "Basic/Command/Base64/"
		$exp2 = "java.lang.ClassCastException: Exploit"
		$exp3 = "WEB-INF/classes/Exploit"
		$exp4 = "Exploit.java"

	condition:
		2 of ($jndi*) and 1 of ($exp*)
}
