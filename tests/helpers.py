def assert_denies(tc, rules):
    for r in ("Read(/etc/**)", "Read(**/.env*)", "Read(**/.git/**)",
              "Grep(**/.env*)", "Glob(**/.env*)", "Read(**/*.pem)", "Bash", "Write", "Edit"):
        tc.assertIn(r, rules.split(","))
