from flask import Flask, request, jsonify
import asyncio, json, binascii, requests, aiohttp, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2, like_count_pb2, uid_generator_pb2
from config import URLS_INFO, URLS_LIKE, FILES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

def load_tokens(server):
    files = FILES
    with open(f"tokens/{files.get(server, 'token_bd.json')}", "r", encoding="utf-8") as f:
        return json.load(f)

def get_headers(token):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
    }

def encrypt_message(data: bytes) -> str:
    cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    enc = cipher.encrypt(pad(data, AES.block_size))
    return binascii.hexlify(enc).decode()

def create_like(uid, region):
    m = like_pb2.like()
    m.uid = int(uid)
    m.region = region
    return m.SerializeToString()

def create_uid(uid):
    m = uid_generator_pb2.uid_generator()
    m.saturn_ = int(uid)
    m.garena = 1
    return m.SerializeToString()

async def send(session, token, url, data):
    headers = get_headers(token)
    async with session.post(url, data=bytes.fromhex(data), headers=headers) as r:
        return await r.text() if r.status == 200 else None

async def multi(uid, server, url):
    enc = encrypt_message(create_like(uid, server))
    tokens = load_tokens(server)
    async with aiohttp.ClientSession() as session:
        tasks = [send(session, t['token'], url, enc) for t in tokens[:105]]
        return await asyncio.gather(*tasks)

def get_info(enc, server, token):
    urls = URLS_INFO
    url = urls.get(server, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
    r = requests.post(url, data=bytes.fromhex(enc), headers=get_headers(token), verify=False)
    try:
        p = like_count_pb2.Info()
        p.ParseFromString(r.content)
        return p
    except DecodeError:
        return None

async def process_uid(uid, server, urls):
    tokens = load_tokens(server)
    enc = encrypt_message(create_uid(uid))
    before, tok = None, None
    for t in tokens[:10]:
        before = get_info(enc, server, t["token"])
        if before:
            tok = t["token"]
            break

    if not before:
        return {"uid": uid, "error": "Player not found", "status": 0}

    before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))
    await multi(uid, server, urls.get(server, "https://clientbp.ggblueshark.com/LikeProfile"))
    after_info = get_info(enc, server, tok)
    if not after_info:
        return {"uid": uid, "error": "After info not found", "status": 0}

    after = json.loads(MessageToJson(after_info))
    after_like = int(after.get('AccountInfo', {}).get('Likes', 0))

    return {
        "credits": "great.thug4ff.com",
        "likes_added": after_like - before_like,
        "likes_before": before_like,
        "likes_after": after_like,
        "player": after.get('AccountInfo', {}).get('PlayerNickname', ''),
        "uid": after.get('AccountInfo', {}).get('UID', 0),
        "status": 1 if after_like - before_like else 2,
    }

@app.route("/like")
def like():
    uid_input = request.args.get("uid")
    server = request.args.get("server", "").upper()
    if not uid_input or not server:
        return jsonify(error="UID and server required"), 400

    # Parse UIDs
    uids = []
    if '-' in uid_input:
        try:
            start, end = map(int, uid_input.split('-'))
            uids = [str(i) for i in range(start, end + 1)]
        except ValueError:
            return jsonify(error="Invalid UID range format"), 400
    else:
        uids = [u.strip() for u in uid_input.split(',') if u.strip().isdigit()]

    if not uids:
        return jsonify(error="No valid UIDs provided"), 400

    urls = URLS_LIKE

    # Dùng loop sẵn thay vì asyncio.run()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(asyncio.gather(*[process_uid(uid, server, urls) for uid in uids]))
    loop.close()

    return jsonify({
        "results": results,
        "total_processed": len(results),
        "credits": "great.thug4ff.com"
    })

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
