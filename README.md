# finger-cgi

CGI finger gateway — C99/kcgi, arena allocation, BSD sandbox, Da Planet stack

## Stack

| Layer  | Technology                        |
|--------|-----------------------------------|
| CGI    | kcgi / kcgihtml (kristapsdz)      |
| Build  | nob.c (tsoding nob.h)             |
| Alloc  | tsoding arena.h                   |
| Policy | OPA / Rego                        |
| Tests  | tests.c (xUnit, C99)              |
| SLSA   | slsa-github-generator Level 3     |

## Build

```sh
curl -sSfL https://raw.githubusercontent.com/tsoding/nob.h/main/nob.h -o nob.h
curl -sSfL https://raw.githubusercontent.com/tsoding/arena/master/arena.h -o arena.h
curl -sSfL https://raw.githubusercontent.com/tsoding/sv/master/sv.h -o sv.h

cc nob.c -o nob && ./nob
./nob test
./nob install
```

## Deployment (panix.com / NetBSD)

```sh
./nob install   # deploys to ~/public_html/cgi-bin/finger.cgi
```

## BDD Workflow

```
issue → feat/N-branch → policy/rego → tests.c → code → changelog → PR → tag
```

## Licence

BSD 2-Clause — see [LICENSE](LICENSE)
