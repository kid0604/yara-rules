rule md5_4c4b3d4ba5bce7191a5138efa2468679
{
	meta:
		description = "Detects PHP code related to Magento and Visbot user agent"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "<?PHP /*** Magento** NOTICE OF LICENSE** This source file is subject to the Open Software License (OSL 3.0)* that is bundled with this package in the file LICENSE.txt.* It is also available through the world-wide-web at this URL:* http://opensource.org/licenses/osl-3.0.php**/$"
		$ = "$_SERVER['HTTP_USER_AGENT'] == 'Visbot/2.0 (+http://www.visvo.com/en/webmasters.jsp;bot@visvo.com)'"

	condition:
		any of them
}
