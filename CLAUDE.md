# go-siit

Stateless IP/ICMP translation (RFC 7915) with RFC 6052 addressing and RFC 7757 explicit address mappings.

## Citing RFCs

Comments that cite an RFC are what the implementation is checked against, so they must be exact.

- Never cite an RFC section from memory. Look it up in the RFC text (`https://www.rfc-editor.org/rfc/rfcNNNN.txt`).
- A requirement is cited with the exact RFC sentence that holds its keyword, and only the relevant part:

  ```go
  // RFC 7915 Section 4.5: "translators MUST forward all transport protocols"
  ```

- A requirement level in parentheses after a citation is only allowed when the quote that follows contains that word.
- Your own explanation goes in a separate paragraph, after an empty `//` line. Never mix a quote and a paraphrase.
- Name the RFC in every sentence that cites one of its sections.
- Never reword, merge or remove an existing RFC quote. If one looks wrong, report it instead.
- Keep code in the order of the RFC, unless performance requires otherwise (then say so in a comment).
- Use numeric ICMP types and codes, as the RFCs do.

Run the checker before finishing a change. It must report 0 problems:

```sh
go run ./tools/rfccheck
```

It verifies that cited sections and figures exist, that quotes appear in the cited section, and that every
requirement label is backed by a quote. It cannot verify that the code does what the quote says: review that.
