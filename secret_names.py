"""
Shared: what counts as a security-sensitive identifier, and how confidently.

ONE source of truth. Every detector imports this rather than carrying its own
copy -- the names, the matching rule, and the precision classes ship together,
so a detector cannot import the sets and then classify them differently.

TWO PRECISION CLASSES. Real-code contact showed the flat list was too blunt:
in a quantitative codebase, `key`, `hash`, `digest` and `sig` overwhelmingly
mean dict key, content hash and statistical significance, not credentials.

    HIGH_PRECISION   names that almost always mean a credential
    COLLISION_PRONE  names that are frequently innocent in real code

MATCHING RULE (unchanged): split the identifier on underscores, lowercase each
component, and match if ANY component is in the union. So secret_token,
user_password and expected_mac match, while "keyboard" and "hashtag" do not
(one component each, not "key" / "hash").

PRECISION RULE:
    1. the whole identifier, or ANY component, is in HIGH_PRECISION -> "high"
       (high precision WINS any tie: secret_key and api_key are "high"
        despite containing "key")
    2. else the whole identifier, or any component, is in COLLISION_PRONE
       -> "collision"
    3. else -> None (not secret-ish)

DISPLAY RULE: a detector's name= field always shows the FULL identifier that
was flagged (api_key, private_key), never the component that matched it. The
component decides precision; the whole identifier is what a reader sees.
"""

HIGH_PRECISION = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "credential", "token", "auth", "session", "cookie",
    # "hmac" is high-precision, not collision-prone: a variable named hmac has
    # no innocent dict-key or statistical meaning.
    "hmac",
}

COLLISION_PRONE = {
    "key", "hash", "digest", "sig", "signature", "mac", "salt", "nonce",
    # Measured demotion. As BARE components these produced 5 false-positive
    # HIGHs (private_metadata, is_private, private_metadata_permissions) and
    # 0 real catches across Saleor and itsdangerous. The catastrophe case --
    # private_key / signing_key / signing_secret -- is rescued by the
    # COMBINATION rule below, not by this class.
    "private", "signing",
}

# COMBINATION rule: a (private|signing) component together with a (key|secret)
# component names an actual private/signing key -- a catastrophe if leaked.
COMBO_QUALIFIER = {"private", "signing"}
COMBO_SUBJECT = {"key", "secret"}

# The flat union -- for consumers that only ask "is this secret-ish at all".
SUSPICIOUS_NAMES = HIGH_PRECISION | COLLISION_PRONE

MATCHING_RULE = (
    "an identifier matches when any UNDERSCORE-SEPARATED COMPONENT, lowercased,\n"
    "  is in the list -- secret_token / user_password / expected_mac match, while\n"
    "  'keyboard' and 'hashtag' do not (one component each, not 'key' / 'hash')."
)

PRECISION_RULE = (
    "high-precision names (%s)\n"
    "  almost always mean a credential; collision-prone names (%s)\n"
    "  are often innocent (dict key, content hash, statistical significance).\n"
    "  COMBINATION rule, checked FIRST: a (private|signing) component together with a\n"
    "  (key|secret) component is \"high\" -- private_key / signing_key / signing_secret\n"
    "  are catastrophes even though BOTH of their components are collision-prone.\n"
    "  Bare private / signing (private_metadata, is_private) stay collision-prone.\n"
    "  Otherwise a name is \"high\" if the whole identifier OR any component is\n"
    "  high-precision, so secret_key and api_key stay \"high\" despite the 'key'."
    % (", ".join(sorted(HIGH_PRECISION)), ", ".join(sorted(COLLISION_PRONE)))
)


def _hits(identifier, names):
    """True if the whole identifier or any underscore component is in `names`."""
    if identifier.lower() in names:
        return True
    return any(part.lower() in names for part in identifier.split("_"))


def matched_component(identifier):
    """Return the component of `identifier` that matched, or None."""
    if not identifier:
        return None
    for part in identifier.split("_"):
        if part.lower() in SUSPICIOUS_NAMES:
            return part
    if identifier.lower() in SUSPICIOUS_NAMES:
        return identifier
    return None


def is_secret_name(identifier):
    """True when the identifier names something security-sensitive (either class)."""
    return matched_component(identifier) is not None


def precision_of(identifier):
    """"high" | "collision" | None -- how confidently this name means a secret.

    ORDER IS LOAD-BEARING. The COMBINATION check MUST run FIRST: private_key is
    private(collision) + key(collision), so if the plain component checks ran
    first it would fall through to "collision" and the catastrophe flag would
    be LOST. The combination check rescues exactly that case. Do not reorder it
    after the component checks.

        1. combination: a (private|signing) component AND a (key|secret)
           component -> "high"  (private_key, signing_key, signing_secret,
                                 private_api_key, get_private_key)
        2. any HIGH_PRECISION component, or the whole identifier -> "high"
        3. any COLLISION_PRONE component, or the whole identifier -> "collision"
        4. else -> None
    """
    if not identifier:
        return None
    parts = {p.lower() for p in identifier.split("_")}
    if (parts & COMBO_QUALIFIER) and (parts & COMBO_SUBJECT):
        return "high"
    if _hits(identifier, HIGH_PRECISION):
        return "high"
    if _hits(identifier, COLLISION_PRONE):
        return "collision"
    return None


def name_list():
    """The full set as a stable, printable string, for auditable output."""
    return ", ".join(sorted(SUSPICIOUS_NAMES))
