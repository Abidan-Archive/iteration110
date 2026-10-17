# Writing spoilers on the wiki

Use spoiler blocks to let readers choose when to reveal plot details. Label each
block with the book (and chapter, if useful) that readers should finish first.
Keep the label itself spoiler-free.

Paste the examples below into the wiki's **source editor**.

## Spoilers extension: focused reveals

Use this style for a short reveal, an answer, or a paragraph that interrupts an
otherwise spoiler-safe article. The content starts hidden, with custom buttons
to show and hide it.

```wikitext
{{#spoiler:show=Show Waybound spoilers|hide=Hide spoilers|
The spoiler content goes here. You can include '''bold text''' and [[links]].
}}
```

The extension also supports a tag form, which is convenient when the content
contains tables or other markup with pipe characters (`|`):

```wikitext
<spoiler show="Show Waybound spoilers" hide="Hide spoilers">
The spoiler content goes here.
</spoiler>
```

In the parser-function form, literal pipes can be interpreted as argument
separators. Prefer the tag form for complicated content and check the preview.

## Built-in collapsible block: larger sections

Use this style for a book-by-book summary, a longer optional section, or content
that needs a permanently visible introduction. It uses MediaWiki's built-in
collapsible elements and does not require the Spoilers extension.

```wikitext
<div class="mw-collapsible mw-collapsed">
'''Waybound spoilers — expand to read'''
<div class="mw-collapsible-content">

The spoiler content goes here.

* A plot detail
* Another plot detail

</div>
</div>
```

The label stays visible; the inner content starts collapsed. Both
`mw-collapsible` and `mw-collapsed` are needed for that initial state.

## Choosing a style

| Situation | Recommended style |
| --- | --- |
| A short reveal among otherwise safe text | Spoilers extension |
| Custom “Show book spoilers” / “Hide spoilers” buttons | Spoilers extension |
| A long summary or optional article section | Built-in collapsible block |
| Content that should work on a wiki without the extension | Built-in collapsible block |

Both styles hide content visually; they do not remove it from page source or
restrict access. Readers must choose what to reveal; neither style tracks their
reading progress automatically.

Keep spoilers out of page titles, visible labels, and image captions outside the
hidden block. Preview edits and check that the content starts hidden and can be
shown and hidden again. Avoid deeply nested spoiler blocks.

## Enabling the extension

The NixOS module in `../modules/mediawiki.nix` includes a pinned Spoilers extension.
After applying the NixOS rebuild, check **Special:Version** for **Spoilers**.
Existing pages need spoiler markup added explicitly.
