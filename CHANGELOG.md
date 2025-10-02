# Changelog

## [1.3.0](https://github.com/KKamJi98/listup-aws-resources/compare/v1.2.0...v1.3.0) (2025-10-02)


### Features

* Add filtered data export to JSON ([215a4b6](https://github.com/KKamJi98/listup-aws-resources/commit/215a4b695689cc798e46bac3a1f8adf87a179202))
* **ec2:** Add Security Group information to EC2 instances ([b597b4c](https://github.com/KKamJi98/listup-aws-resources/commit/b597b4c73971cbe4ed72489b493ff6808a59de81))
* **security:** Add security group rules module and improve file generation ([9f5581e](https://github.com/KKamJi98/listup-aws-resources/commit/9f5581ed8f612dcdce6ebaa854e751ba70ec95ba))
* Track security group usage and expand outputs ([b5c88e2](https://github.com/KKamJi98/listup-aws-resources/commit/b5c88e219795ccfb653cc6bc9f865a90fbf9b2a7))
* **security-groups:** Track attached resources and expose usage counts
* **cli:** Export results to timestamped directories with Excel, CSV, and JSON outputs
* **cli:** Add CSV flattening helper for filtered data


### Documentation

* Tidy changelog entries ([9bd964a](https://github.com/KKamJi98/listup-aws-resources/commit/9bd964aa0fdfb3f4b47e3eb9f1b9c0c85ff31d96))
* **README:** Document new output layout and add full execution example
* **AGENTS:** Reflect Security Group usage tracking and multi-format exports

## [1.2.0](https://github.com/KKamJi98/listup_aws_resources/compare/v1.1.0...v1.2.0) (2025-07-21)


### Features

* **main:** Add SES identity resource collection to main script ([39e1b6f](https://github.com/KKamJi98/listup_aws_resources/commit/39e1b6f9b2d29b32db5a5f361039bb728c92b3f9))
* **ses:** improve SES identity module with datetime formatting and add tests ([a5bd9f4](https://github.com/KKamJi98/listup_aws_resources/commit/a5bd9f456fb4bd8a265b53832cad3d7ad3850ed0))
* **utils:** add datetime formatting utility function ([372f503](https://github.com/KKamJi98/listup_aws_resources/commit/372f5032424994da9854ec903c9433fcd4e9efaf))


### Documentation

* update README and streamline package management ([08c64b6](https://github.com/KKamJi98/listup_aws_resources/commit/08c64b6d3676f5f2178a908dd658a2e9d5d51abb))

## [1.1.0](https://github.com/KKamJi98/listup_aws_resources/compare/v1.0.0...v1.1.0) (2025-07-02)


### Features

* Add GEMINI.md and configure isort/black for consistent formatting ([27913f7](https://github.com/KKamJi98/listup_aws_resources/commit/27913f77ac3ab179cd79e6a944c2ac8184dfb2e7))
* **deps:** Add uv.lock for reproducible builds ([e13ba4b](https://github.com/KKamJi98/listup_aws_resources/commit/e13ba4b2cac147a47e6a430b28ad1ece98e56c90))
* poetry to uv and add new resources ([4bef37c](https://github.com/KKamJi98/listup_aws_resources/commit/4bef37c783c0d05f40125441a208d6042750e400))
* uv 가상 환경 설정 및 테스트 코드 개선 ([3db4483](https://github.com/KKamJi98/listup_aws_resources/commit/3db4483951be2b9fc348d97dd001fd9a909b71d0))
* uv 가상환경 설정 및 CI/CD 파이프라인 업데이트 ([d188af3](https://github.com/KKamJi98/listup_aws_resources/commit/d188af3bce4525930c60fad3c95c7f25a551511a))


### Bug Fixes

* CI workflow to use uv virtual environment and pass checks ([a363c2f](https://github.com/KKamJi98/listup_aws_resources/commit/a363c2f01ba465184e6a2691c14af7f9d1d51740))
* **ci:** Correct venv activation and dependencies ([b52035c](https://github.com/KKamJi98/listup_aws_resources/commit/b52035cb32cf241e8693d556dc4e51b8c8ae161f))
* CI에서 boto3 ModuleNotFoundError 해결 ([260b62c](https://github.com/KKamJi98/listup_aws_resources/commit/260b62cfd1dff7af98093f3179d1049f09df0ffc))
* **deps:** Add explicit botocore version ([791cd97](https://github.com/KKamJi98/listup_aws_resources/commit/791cd977f8f817702dbddfc0eaa47d5abd6f2027))
* resolve package build and CI errors ([6150162](https://github.com/KKamJi98/listup_aws_resources/commit/61501627a6890b43dee51c4bfe20da587102862e))
* **style:** Apply black formatting to listup_aws_resources.py ([5c4e6d4](https://github.com/KKamJi98/listup_aws_resources/commit/5c4e6d4ca60ee3c317c7dca9f20ab18c746341a8))
* **test:** Handle argparse in test environment ([d299d71](https://github.com/KKamJi98/listup_aws_resources/commit/d299d71446dce1e63b848f419b580f3a5bab166f))


### Reverts

* Remove GEMINI.md from git tracking again ([c74dd8d](https://github.com/KKamJi98/listup_aws_resources/commit/c74dd8d896807059f815b39fb2b6ebba442245ca))


### Documentation

* Add Conventional Commits rule to GEMINI.md ([5c4e6d4](https://github.com/KKamJi98/listup_aws_resources/commit/5c4e6d4ca60ee3c317c7dca9f20ab18c746341a8))
* add GEMINI.md and ensure all checks pass ([00a2758](https://github.com/KKamJi98/listup_aws_resources/commit/00a275831f184dd14f2b955a6bdf74ff05165fee))
* CHANGELOG.md 버전 형식을 vX.Y.Z로 수정 ([ddf3b1d](https://github.com/KKamJi98/listup_aws_resources/commit/ddf3b1dbe552d1d8f97db4ff915f82bdc5ee01ce))
* Merge .prompt.md into GEMINI.md and remove .prompt.md ([67ea01a](https://github.com/KKamJi98/listup_aws_resources/commit/67ea01a313b012775659eeb104e55d68b9cd1b77))
* Update project history and requirements ([059edaa](https://github.com/KKamJi98/listup_aws_resources/commit/059edaa43f9b71be531392e362fb91fdf9106c53))

## [v1.0.0] - 2025-05-28

### 추가
- Security Group 리소스 조회 기능 추가
- 0.0.0.0/0 AnyOpen된 Inbound Rule을 가진 Security Group은 '⚠️ YES'로 표시
- CHANGELOG.md 파일 추가

### 변경
- 버전을 0.1.0에서 1.0.0으로 업데이트
- README.md 파일 업데이트: Security Group 관련 기능 설명 추가

## [v0.1.0] - 2025-03-30

### 추가
- 초기 프로젝트 구조 설정
- 다양한 AWS 리소스 조회 기능 구현 (EC2, VPC, RDS, EKS, S3, DynamoDB 등)
- Excel 및 JSON 형식으로 데이터 내보내기 기능
