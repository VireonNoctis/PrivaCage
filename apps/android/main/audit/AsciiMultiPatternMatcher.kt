package org.privacage.audit

import java.util.ArrayDeque

/** A literal, printable-ASCII pattern for scanning binary buffers such as DEX string data. */
data class AsciiSearchPattern(
    val id: String,
    val value: String
)

/**
 * Incremental, case-insensitive multi-pattern matcher. Aho-Corasick failure links keep the state
 * across chunks, so matches split across input-buffer boundaries are found without reading an
 * entire DEX file into memory.
 */
class AsciiMultiPatternMatcher(patterns: List<AsciiSearchPattern>) {
    private class Node {
        val children = HashMap<Char, Node>()
        val outputs = LinkedHashSet<String>()
        var failure: Node? = null
    }

    private val root = Node()
    private var state: Node = root

    init {
        require(patterns.all { it.id.isNotBlank() }) { "Pattern IDs must not be blank" }
        for (pattern in patterns) {
            require(pattern.value.isNotEmpty()) { "Pattern values must not be empty" }
            require(pattern.value.all { it.code in 0x20..0x7e }) {
                "Patterns must be printable ASCII literals"
            }

            var node = root
            for (character in pattern.value.map(::foldAscii)) {
                node = node.children.getOrPut(character) { Node() }
            }
            node.outputs += pattern.id
        }
        buildFailureLinks()
    }

    /** Starts an independent byte stream without rebuilding the compiled pattern automaton. */
    fun reset() {
        state = root
    }

    /**
     * Feeds a chunk and returns identifiers matched in this chunk, including matches that began
     * in a previous chunk. Callers reset before each independent file/stream.
     */
    fun feed(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): Set<String> {
        require(offset in 0..bytes.size && length >= 0 && length <= bytes.size - offset) {
            "Chunk range is outside the supplied byte array"
        }
        val matched = LinkedHashSet<String>()
        for (index in offset until offset + length) {
            val character = foldAscii((bytes[index].toInt() and 0xff).toChar())
            while (state !== root && state.children[character] == null) {
                state = state.failure ?: root
            }
            state = state.children[character] ?: root
            matched += state.outputs
        }
        return matched
    }

    private fun buildFailureLinks() {
        root.failure = root
        val queue = ArrayDeque<Node>()
        for (child in root.children.values) {
            child.failure = root
            queue.addLast(child)
        }

        while (queue.isNotEmpty()) {
            val parent = queue.removeFirst()
            val parentFailure = parent.failure ?: root
            for ((character, child) in parent.children) {
                var fallback = parentFailure
                while (fallback !== root && fallback.children[character] == null) {
                    fallback = fallback.failure ?: root
                }
                child.failure = fallback.children[character] ?: root
                child.outputs.addAll(child.failure!!.outputs)
                queue.addLast(child)
            }
        }
    }

    private fun foldAscii(character: Char): Char =
        if (character in 'A'..'Z') (character.code + ('a'.code - 'A'.code)).toChar() else character
}
