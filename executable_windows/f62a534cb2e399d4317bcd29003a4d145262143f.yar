import "pe"

rule MAL_Malware_Imphash_Mar23_1
{
	meta:
		description = "Detects malware by known bad imphash or rich_pe_header_hash"
		reference = "https://yaraify.abuse.ch/statistics/"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
		author = "Arnim Rupp"
		date = "2023-03-20"
		modified = "2023-03-22"
		score = 75
		hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
		hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
		hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
		hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
		hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
		hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
		hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
		hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
		hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
		hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
		hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
		hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
		hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
		hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
		hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
		hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
		hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
		hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
		hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
		hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
		hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
		hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
		hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
		hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
		hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
		hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
		hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
		hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
		hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
		hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
		hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
		hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
		hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
		hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
		hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
		hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
		hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
		hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
		hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
		hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
		hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
		hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
		hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
		os = "windows"
		filetype = "executable"

	strings:
		$fp1 = "Win32 Cabinet Self-Extractor" wide
		$fp2 = "EXTRACTOPT" ascii fullword

	condition:
		uint16(0)==0x5A4D and (pe.imphash()=="9ee34731129f4801db97fd66adbfeaa0" or pe.imphash()=="f9e8597c55008e10a8cdc8a0764d5341" or pe.imphash()=="0a76016a514d8ed3124268734a31e2d2" or pe.imphash()=="d3cbd6e8f81da85f6bf0529e69de9251" or pe.imphash()=="d8b32e731e5438c6329455786e51ab4b" or pe.imphash()=="cdf5bbb8693f29ef22aef04d2a161dd7" or pe.imphash()=="890e522b31701e079a367b89393329e6" or pe.imphash()=="bf5a4aa99e5b160f8521cadd6bfe73b8" or pe.imphash()=="646167cce332c1c252cdcb1839e0cf48" or pe.imphash()=="9f4693fc0c511135129493f2161d1e86" or pe.imphash()=="b4c6fff030479aa3b12625be67bf4914") and not 1 of ($fp*)
}
