package playground

/**
 * The PLAYGROUND_* environment knobs, the way the C# samples read them: the sample's literal is its
 * configuration, and a set variable overrides it. Unparseable values fall back to the literal.
 */
object Env {
    fun int(name: String, fallback: Int): Int = System.getenv(name)?.toIntOrNull() ?: fallback

    fun port(fallback: Int): Int = int("PLAYGROUND_PORT", fallback)

    fun reactors(fallback: Int): Int = int("PLAYGROUND_REACTORS", fallback)

    fun body(fallback: Int): Int = int("PLAYGROUND_BODY", fallback)

    /** 1/true/yes switch a knob on, 0/false/no off; anything else keeps the literal. */
    fun bool(name: String, fallback: Boolean): Boolean = when (System.getenv(name)?.lowercase()) {
        "1", "true", "yes" -> true
        "0", "false", "no" -> false
        else -> fallback
    }

    fun string(name: String): String? = System.getenv(name)?.takeIf { it.isNotBlank() }
}
