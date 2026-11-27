# PipelineGuard — aasan zabaan mein

## Ye kya hai?
GitHub Actions ki workflow files (`.github/workflows/*.yml`) wo code hain jo aap ke **secrets** aur **token** ke saath chalta hai.
PipelineGuard in files ko parhta hai (chalata nahi) aur batata hai ke kahan khatra hai, kahan pipeline slow ya mehngi hai,
aur aakhir mein ek faisla deta hai: **PASS**, **WARN** ya **FAIL** + 0 se 100 tak score.

## 3 bare khatre (examples)
1. **Pwn request** — `pull_request_target` workflow agar fork ka code checkout kare to bahar ka banda aap ke secrets ke saath code chala sakta hai.
2. **Script injection** — `run: echo "${{ github.event.pull_request.title }}"` — PR ka title seedha shell mein chala jata hai. Title mein command likh do to wo chal jati hai.
3. **Unpinned action** — `uses: kisi/action@v1` — tag kabhi bhi badla ja sakta hai. March 2025 mein `tj-actions/changed-files` ke saath yehi hua tha. Hal: poora commit SHA likho.

## Auto-fix kya karta hai?
Jo cheezein mechanical hain (timeout, cache, permissions, purane versions, `npm install` → `npm ci`, title ko `env:` mein le jana)
wo khud theek kar ke **diff** dikhata hai. Aap ki file ke comments aur formatting kharab nahi hoti. Fix ke baad file dobara check hoti hai, aur naya score bhi dikhata hai.

## Chalana kaise hai (Windows)
```
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn pipelineguard.api:app --port 8200
```
Doosra terminal:
```
cd frontend
npm ci
npm run dev
```
Browser mein `http://localhost:5175` kholo → **Audit Workflows** → koi sample chuno → **Run PipelineGuard**.

## CLI
```
cd backend
python -m pipelineguard pipelineguard/samples/pwn-request-bot
```
Exit code 1 = FAIL (CI ruk jayega), 0 = PASS/WARN.

## Interview mein kaise samjhaun?
"Maine ek static analyzer banaya hai jo GitHub Actions workflows ko parse kar ke 24 security, supply-chain, reliability aur
performance rules chalata hai, PR ko gate karta hai, SARIF deta hai taake findings GitHub Code Scanning mein aayein,
aur safe auto-fix ka diff banata hai. Ye apni CI mein khud ko bhi audit karta hai (dogfooding)."
