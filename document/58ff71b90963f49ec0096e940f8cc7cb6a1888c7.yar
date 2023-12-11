rule attachment_alt_1 : mail
{
	meta:
		author = "A.Sanchez <asanchez@koodous.com>"
		description = "Detects scam emails with phishing attachment."
		test1 = "email/eml/transferencia1.eml"
		test2 = "email/eml/transferencia2.eml"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$filename = "filename=\"scan001.pdf.html\""
		$pleaseEnter = "NTAlNkMlNjUlNjElNzMlNjUlMjAlNjUlNkUlNzQlNjUlNzIlMjAlN"
		$emailReq = "NkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUlNzglMzIlMkUlNDUlNkQlNjElNjklNkMlM0I"
		$pAssign = "NzAlMjAlM0QlMjAlNjQlNkYlNjMlNzUlNkQlNjUlNkUlNzQlMkUlNjklNkUlNjQlNjUl"

	condition:
		all of them
}
