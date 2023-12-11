rule dump_sales_quote_payment
{
	meta:
		description = "Detects potential dumping of sales quote payment information from Magento"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ = "include '../../../../../../../../../../app/Mage.php'; Mage::app(); $q = Mage::getModel('sales/quote_payment')->getCollection();"

	condition:
		any of them
}
