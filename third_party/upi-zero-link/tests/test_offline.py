"""离线自测：核验判据、指纹稳定性、地址池。不联网。"""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from upi_zero_link import addresses, identity, verify  # noqa: E402


def payload_b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def page(data: dict) -> str:
    return '<html><meta id="payload" data-message="%s"></html>' % payload_b64(data)


GOOD = {"intent_state": "requires_action",
        "mobile_auth_url": "upi://mandate?am=1999.00&fam=1.00"}
DEAD = {"intent_state": "requires_payment_method",
        "mobile_auth_url": "upi://mandate?am=1999.00&fam=1.00"}
PAYMENT = {"intent_state": "requires_action",
           "mobile_auth_url": "upi://mandate?am=1999.00&fam=1999.00"}
CANCELED = {"intent_state": "canceled",
            "mobile_auth_url": "upi://mandate?am=1999.00&fam=1.00"}


def check(name, condition):
    print("%-34s %s" % (name, "OK" if condition else "FAIL"))
    return bool(condition)


def main() -> int:
    ok = True
    ok &= check("真链判为真", verify.judge(verify.decode_payload(page(GOOD)))[0] is True)
    ok &= check("被拒链判为废", verify.judge(verify.decode_payload(page(DEAD)))[0] is False)
    ok &= check("fam=1999 判为付款链", verify.judge(verify.decode_payload(page(PAYMENT)))[0] is False)
    ok &= check("canceled 判为废", verify.judge(verify.decode_payload(page(CANCELED)))[0] is False)
    ok &= check("没有 payload 时判废", verify.decode_payload("<html></html>") is None)

    class Response:
        status_code = 200
        text = page(GOOD)

    def fetch(url, timeout=0, headers=None, proxies=None):
        return Response

    ok &= check("verify_url 走通",
                verify.verify_url("https://example.test/x", fetch)[0] is True)
    Response.status_code = 410
    ok &= check("410 判为失效链",
                verify.verify_url("https://example.test/x", fetch)[1] == "http_410")

    def broken(url, timeout=0, headers=None, proxies=None):
        raise OSError("no route")

    ok &= check("读不到时返回 unreachable 且算没结论",
                verify.verify_url("https://example.test/x", broken, attempts=1)[1] == "unreachable"
                and "unreachable" in verify.INCONCLUSIVE)
    ok &= check("空 URL 直接拒绝", verify.verify_url("")[1] == "empty_url")

    fp1 = identity.fingerprint("token-abc", "IN")
    fp2 = identity.fingerprint("token-abc", "IN")
    fp3 = identity.fingerprint("token-xyz", "IN")
    ok &= check("同 token 指纹稳定", fp1 == fp2)
    ok &= check("不同 token 指纹不同", fp1["device_id"] != fp3["device_id"])
    ok &= check("印度时区", fp1["timezone"] == "Asia/Kolkata")

    seen = {addresses.next_address()["key"] for _ in range(40)}
    ok &= check("地址池 40 条不重复", len(seen) == 40)
    sample = addresses.next_address()
    ok &= check("地址字段齐全",
                all(sample.get(k) for k in ("name", "line1", "city", "state", "postal_code")))

    print("结果：%s" % ("全部通过" if ok else "有失败项"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
