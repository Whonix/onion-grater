Comprehensive tests for onion-grater -- profile regression and reproduction
tests, adversarial control-command probes, and a full-stack end-to-end suite --
are too high-volume for human review and live in the AI-maintained dist-ai
repo, not here:

  https://github.com/org-ai-assisted/dist-ai -> usr/share/onion-grater-tests/

Run them against this checkout:

    ONION_GRATER_REPO="$PWD" onion-grater-tests       # in-process unit / reproduction
    ONION_GRATER_REPO="$PWD" onion-grater-tests-e2e   # full-stack (needs tor + sudo)
