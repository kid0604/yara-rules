rule content_alt_1 : mail
{
	meta:
		author = "A.Sanchez <asanchez@koodous.com>"
		description = "Detects scam emails with phishing attachment."
		test1 = "email/eml/transferencia1.eml"
		test2 = "email/eml/transferencia2.eml"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$subject = "Asunto: Justificante de transferencia" nocase
		$body = "Adjunto justificante de transferencia"

	condition:
		all of them
}
