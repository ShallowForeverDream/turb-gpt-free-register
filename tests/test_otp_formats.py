import unittest

from core.otp_formats import best_candidate, extract_candidates, normalize_otp, split_grouped


class NormalizeOtpTests(unittest.TestCase):
    def test_accepts_supported_shapes(self):
        cases = {
            "123456": "123456",
            " 123 456 ": "123456",
            "123-456": "123-456",
            "1234-5678": "1234-5678",
            "12345678": "12345678",
            "A1B2C3": "A1B2C3",
            "AB12CD": "AB12CD",
            "A1B2-C3D": "A1B2-C3D",
            "abcd12": "abcd12",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_otp(raw), expected)

    def test_unifies_dash_variants_and_ignores_spacing(self):
        for raw in ("123\u2013456", "123\u2014456", "123\u2212456", "123\uff0d456", "123 \u2013 456"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_otp(raw), "123-456")
        self.assertEqual(normalize_otp("98 \u2013 57 \u2013 22 \u2013 01"), "98572201")
        self.assertEqual(normalize_otp("ABCD\u2014EFGH"), "ABCD-EFGH")

    def test_rejects_non_code_values(self):
        for raw in (None, True, 123, "", "12345", "1234567", "123456789", "ab12", "hello",
                    "\uff11\uff12\uff13\uff14\uff15\uff16", "123456789012345678901234567890123"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_otp(raw), "")

    def test_split_grouped(self):
        self.assertEqual(split_grouped("123-456"), ("123", "456"))
        self.assertEqual(split_grouped("123456"), ("", "123456"))
        self.assertEqual(split_grouped("not-a-code-but-long"), ("", ""))


class ExtractCandidatesTests(unittest.TestCase):
    def test_numeric_six_and_eight_digits(self):
        self.assertEqual(best_candidate("Your verification code is 448210."), "448210")
        self.assertEqual(best_candidate("Your 8-digit code is 12345678"), "12345678")
        self.assertEqual(best_candidate("Your code is 1234-5678"), "1234-5678")

    def test_alphanumeric_and_dashed_mixed_codes(self):
        self.assertEqual(best_candidate("Your Grok code: A1B2-C3D"), "A1B2-C3D")
        self.assertEqual(best_candidate("验证码：AB12CD"), "AB12CD")
        self.assertEqual(best_candidate("Your code is A1B-2C3"), "A1B-2C3")
        self.assertEqual(best_candidate("Ваш код: 98 – 57 – 22 – 01"), "98572201")
        self.assertEqual(best_candidate("Security code: ABCD-EFGH"), "ABCD-EFGH")
        self.assertEqual(best_candidate("Your code: A1B-2C-3D"), "A1B-2C-3D")

    def test_mixed_code_is_not_truncated_or_mistaken_for_a_word(self):
        self.assertEqual(extract_candidates("Your Grok code: A1B2-C3D"), ["A1B2-C3D"])
        self.assertEqual(extract_candidates("Your code is A1B-2C3, not A1B2-C3DX"), ["A1B-2C3"])
        for text in ("queue-2v restarted", "49-level path", "socks5 host", "https url"):
            with self.subTest(text=text):
                self.assertEqual(extract_candidates(text), [])

    def test_codes_from_an_older_message_are_kept_separate(self):
        older, newer = "Your verification code is 111222", "Your code is 333444"
        self.assertEqual(best_candidate(newer), "333444")
        # Like the old API, the newest message is searched first.
        self.assertEqual(extract_candidates(newer, older), ["111222", "333444"])

    def test_dashed_numeric_code(self):
        self.assertEqual(best_candidate("验证码：123-456。"), "123-456")
        self.assertEqual(best_candidate("One-time code 123 456"), "123456")

    def test_html_and_localized_context(self):
        html = "<style>.x{color:#353740}</style><p>認証コード</p><strong>741-852</strong>"
        self.assertEqual(best_candidate(html), "741-852")
        self.assertEqual(best_candidate("<div>Ваш код</div><div>8811-2299</div>"), "8811-2299")

    def test_noise_is_not_offered_as_a_code(self):
        for text in ("Order id 123456 shipped", "Amount 1,234,567", "Expires 2026-1030",
                     "Reference #87654321", "model 353740", "HTTP 200 OK", "version 3537400",
                     "color #353740", "tel 1234567", "订单号 998877"):
            with self.subTest(text=text):
                self.assertEqual(extract_candidates(text), [])

    def test_labelled_code_wins_over_other_numbers(self):
        text = "Order id 998877 on 2026-10-30. Your verification code is 445566."
        self.assertEqual(extract_candidates(text)[0], "445566")
        self.assertNotIn("998877", extract_candidates(text))

    def test_repeated_plain_and_grouped_form_is_one_candidate(self):
        text = "Your code is 123-456. Enter 123-456 to continue. Do not share 123-456."
        self.assertEqual(extract_candidates(text), ["123-456"])

    def test_multiple_codes_are_all_returned_in_rank_order(self):
        text = "验证码 445566, 备用验证码 112233"
        self.assertEqual(extract_candidates(text), ["445566", "112233"])

    def test_limit_and_empty_input(self):
        self.assertEqual(extract_candidates(""), [])
        self.assertEqual(extract_candidates(None, ""), [])
        text = " ".join(f"验证码 {value}" for value in ("111222", "333444", "555666"))
        self.assertEqual(len(extract_candidates(text, limit=2)), 2)
        self.assertEqual(len(extract_candidates(text)), 3)


if __name__ == "__main__":
    unittest.main()
