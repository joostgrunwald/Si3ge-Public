import unittest  
from io import StringIO  
from unittest.mock import patch  
import ipaddress  
from preprocess import is_ip, is_cidr, is_ip_port, is_cidr_port, hostname_to_ip, extract_hostname, merge_cidr_ranges, exclude_ips, process_input  
from netaddr import IPNetwork, cidr_merge

class TestScript(unittest.TestCase):  
  
    def test_is_ip(self):  
        self.assertTrue(is_ip('192.168.1.1'))  
        self.assertTrue(is_ip('255.255.255.255'))  
        self.assertTrue(is_ip('0.0.0.0'))  
        self.assertTrue(is_ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334'))  
        self.assertFalse(is_ip('192.168.1.300'))  
        self.assertFalse(is_ip('example.com'))  

    def test_is_ip_port(self):
        self.assertTrue(is_ip_port('192.168.1.1:20'))
        self.assertTrue(is_ip_port('10.0.0.1:8080'))
        self.assertTrue(is_ip_port('172.16.0.1:443'))
        self.assertFalse(is_ip_port('192.168.1.300:80'))
        self.assertFalse(is_ip_port('example.com:80'))
  
    def test_is_cidr(self):  
        self.assertTrue(is_cidr('192.168.1.0/24'))  
        self.assertTrue(is_cidr('2001:db8::/32'))  
        self.assertFalse(is_cidr('192.168.1.1'))  
        self.assertFalse(is_cidr('2001:db8::'))  
        self.assertFalse(is_cidr('example.com'))  

    def test_is_cidr_port(self):
        self.assertTrue(is_cidr_port('192.168.1.0/24:80'))
        self.assertTrue(is_cidr_port('2001:db8::/32:443'))
        self.assertFalse(is_cidr_port('192.168.1.1:80'))
        self.assertFalse(is_cidr_port('example.com:80'))
        self.assertFalse(is_cidr_port('192.168.1.0/24'))
        self.assertFalse(is_cidr_port('2001:db8::/32'))
        self.assertFalse(is_cidr_port('example.com'))
  
    def test_hostname_to_ip(self):  
        self.assertEqual(hostname_to_ip('example.com'), '93.184.216.34')  
        self.assertIsNone(hostname_to_ip('nonexistent.example.com'))  
  
    def test_extract_hostname(self):  
        self.assertEqual(extract_hostname('https://www.example.com'), 'example.com')  
        self.assertEqual(extract_hostname('http://example.com'), 'example.com')  
        self.assertEqual(extract_hostname('example.com'), 'example.com')  
        self.assertEqual(extract_hostname('https://www.example.com:8080'), 'example.com')  
        self.assertEqual(extract_hostname('https://www.example.com:8080/test'), 'example.com')  
        self.assertIsNone(extract_hostname(''))  
  
    def test_merge_cidr_ranges(self):  
        # Basic accumulation
        cidr_ranges = ['192.168.1.0/24', '192.168.2.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.1.0/24'),IPNetwork('192.168.2.0/24')])

        cidr_ranges = ['192.168.0.0/24', '192.168.1.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.0.0/23')])
        # More advanced accumulation
        cidr_ranges = ['192.168.0.0/24', '192.168.1.0/24', '192.168.2.0/24', '192.168.3.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.0.0/22')])

        # No simplification possible
        cidr_ranges = ['192.168.1.0/24', '192.168.3.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.1.0/24'), IPNetwork('192.168.3.0/24')])

        # Half simplification possible
        cidr_ranges = ['192.168.0.0/24', '192.168.1.0/24', '192.168.3.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.0.0/23'), IPNetwork('192.168.3.0/24')])

        # Subrange can be forgotten about
        cidr_ranges = ['192.168.1.0/24', '192.168.1.128/25']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.1.0/24')])

        # Test when all CIDR ranges are the same
        cidr_ranges = ['192.168.1.0/24', '192.168.1.0/24', '192.168.1.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.1.0/24')])

        # Test when all CIDR ranges are disjoint
        cidr_ranges = ['192.168.1.0/24', '192.168.2.0/24', '192.168.3.0/24']
        merged_ranges = merge_cidr_ranges(cidr_ranges)
        self.assertEqual(merged_ranges, [IPNetwork('192.168.1.0/24'), IPNetwork('192.168.2.0/23')])
  
    def test_exclude_ips(self):  
        cidr_ranges = ['192.168.1.0/24']  
        exclude_ips_list = ['192.168.1.1', '192.168.1.128']  
        result_ranges = exclude_ips(cidr_ranges, exclude_ips_list)  
        expected_ranges = ['192.168.1.0/32', '192.168.1.2/31', '192.168.1.4/30', '192.168.1.8/29',  
                           '192.168.1.16/28', '192.168.1.32/27', '192.168.1.64/26', '192.168.1.129/32',  
                           '192.168.1.130/31', '192.168.1.132/30', '192.168.1.136/29', '192.168.1.144/28',  
                           '192.168.1.160/27', '192.168.1.192/26']  
        self.assertEqual([str(cidr) for cidr in result_ranges], expected_ranges)  

        cidr_ranges = ['192.168.1.0/24', '192.168.2.0/24']  
        exclude_ips_list = ['192.168.1.1', '192.168.1.128', '192.168.2.128', '192.168.2.254']  
        result_ranges = exclude_ips(cidr_ranges, exclude_ips_list)  
        expected_ranges = ['192.168.1.0/32', '192.168.1.2/31', '192.168.1.4/30', '192.168.1.8/29',  
                        '192.168.1.16/28', '192.168.1.32/27', '192.168.1.64/26', '192.168.1.129/32',  
                        '192.168.1.130/31', '192.168.1.132/30', '192.168.1.136/29', '192.168.1.144/28',  
                        '192.168.1.160/27', '192.168.1.192/26', '192.168.2.0/25', '192.168.2.129/32',  
                        '192.168.2.130/31', '192.168.2.132/30', '192.168.2.136/29', '192.168.2.144/28',  
                        '192.168.2.160/27', '192.168.2.192/27', '192.168.2.224/28', '192.168.2.240/29',  
                        '192.168.2.248/30', '192.168.2.252/31', '192.168.2.255/32']  
        self.assertEqual([str(cidr) for cidr in result_ranges], expected_ranges)  

        cidr_ranges = ['192.168.1.1/32']  
        exclude_ips_list = []  
        result_ranges = exclude_ips(cidr_ranges, exclude_ips_list)  
        expected_ranges = ['192.168.1.1/32']  
        self.assertEqual([str(cidr) for cidr in result_ranges], expected_ranges)  

        cidr_ranges = []  
        exclude_ips_list = ['192.168.1.1', '192.168.1.128']  
        result_ranges = exclude_ips(cidr_ranges, exclude_ips_list)  
        expected_ranges = []  
        self.assertEqual([str(cidr) for cidr in result_ranges], expected_ranges)  

        #TODO: fix small problem here??
        cidr_ranges = ['192.168.1.0/24']  
        exclude_ips_list = ['192.168.1.1', '192.168.1.2']  
        result_ranges = exclude_ips(cidr_ranges, exclude_ips_list)  
        expected_ranges = ['192.168.1.0/32', '192.168.1.3/29', '192.168.1.8/29', '192.168.1.16/28',  
                           '192.168.1.32/27', '192.168.1.64/26', '192.168.1.128/25']  
        self.assertEqual([str(cidr) for cidr in result_ranges], expected_ranges)  
  
    @patch('builtins.open', new=StringIO('192.168.1.1\nexample.com'))  
    def test_process_input(self, mock_open):  
        cidr_ranges = process_input('input_file.txt')  
        self.assertEqual(cidr_ranges, ['192.168.1.1/32', '93.184.216.34/32'])  
  
    @patch('builtins.open', new=StringIO('192.168.1.0/24\nexample.com'))  
    @patch('preprocess.exclude_ips')  
    def test_process_input_with_exclude_file(self, mock_exclude_ips, mock_open):  
        mock_exclude_ips.return_value = [ipaddress.ip_network('192.168.1.0/25')]  
        cidr_ranges = process_input('input_file.txt', 'exclude_file.txt')  
        self.assertEqual(cidr_ranges, ['192.168.1.0/25', '93.184.216.34/32'])  
        mock_exclude_ips.assert_called_once()  
  
if __name__ == '__main__':  
    unittest.main()  
