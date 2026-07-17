# Testing policy

Every behavior change starts with a test that expresses the intended business
or operational outcome. The test must fail before the implementation changes
and pass afterwards. Tests exist to protect real contracts, not to inflate a
test count or assert incidental implementation text.

For reusable automation, a meaningful test proves a safety or compatibility
property: for example, a backup excludes secret material, a release cannot
move a compatibility tag after a failed validation, or a local validation run
records a failed required command. A test may inspect workflow text when that
text is the executable policy, but it must assert the policy rather than a
cosmetic message.

Run the relevant focused test during development, then run the complete suite
before requesting review:

```powershell
python -m unittest discover -v
```

Do not merge code whose intended behavior lacks a meaningful regression test,
unless the change is documentation-only and cannot alter runtime behavior.
