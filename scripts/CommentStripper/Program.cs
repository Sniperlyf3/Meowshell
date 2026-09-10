using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

var dryRun = args.Contains("--dry-run");
var root = args.FirstOrDefault(a => !a.StartsWith("--")) ?? ".";

var files = Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
    .Where(f => !PathHasSegment(f, "bin") && !PathHasSegment(f, "obj") && !PathHasSegment(f, ".git"))
    .OrderBy(f => f, StringComparer.Ordinal)
    .ToList();

var changed = 0;
foreach (var path in files)
{
    var original = await File.ReadAllTextAsync(path);
    var tree = CSharpSyntaxTree.ParseText(original, path: path);
    var root2 = (CompilationUnitSyntax)await tree.GetRootAsync();
    var stripped = (CompilationUnitSyntax)new CommentStripper().Visit(root2)!;
    var result = CollapseBraceBlankLines(stripped.ToFullString());

    if (result == original) continue;
    changed++;
    if (dryRun)
    {
        Console.WriteLine(path);
        continue;
    }
    await File.WriteAllTextAsync(path, result);
}
Console.Error.WriteLine($"{changed}/{files.Count} files had comments stripped");

static bool PathHasSegment(string path, string segment) =>
    path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Contains(segment);

// Drops a blank line left directly inside a brace pair -- right after the
// line that opens it, or right before the line that closes it -- the shape
// a removed comment that used to be the first or last line of a block
// leaves behind. The trivia-level Filter pass has no way to see this: an
// empty line at the very start of a block is legitimate C# either way, so
// nothing there removes it on its own.
static string CollapseBraceBlankLines(string src)
{
    var lines = src.Split('\n');
    var outLines = new List<string>(lines.Length);
    for (var i = 0; i < lines.Length; i++)
    {
        var cur = lines[i];
        if (cur.TrimEnd(' ', '\t').EndsWith('{') && i + 1 < lines.Length && lines[i + 1].Trim() == "")
        {
            outLines.Add(cur);
            i++;
            continue;
        }
        if (cur.Trim() == "" && i + 1 < lines.Length && lines[i + 1].TrimStart().StartsWith('}'))
        {
            continue;
        }
        outLines.Add(cur);
    }
    return string.Join('\n', outLines);
}

// Removes every comment/doc-comment trivia node (line, block, and /// or /** */
// documentation comments alike -- each is its own SyntaxTriviaList entry, so
// filtering by kind catches multi-line and doc comments the same way as
// single-line ones) while leaving string/char literal content untouched, since
// Roslyn's own parser already separated trivia from token/literal content
// correctly. Three passes over each token's trivia:
//
//  1. Drop every comment-kind trivia node outright. A /// or /** */ doc
//     comment's own trivia text bundles its trailing newline (a plain // or
//     /* */ comment does not -- that newline is always a separate
//     EndOfLineTrivia entry that survives this pass untouched), so dropping a
//     doc comment can leave two whitespace runs directly adjacent with no
//     newline between them.
//  2. Collapse whitespace: a WhitespaceTrivia entry immediately followed by
//     another WhitespaceTrivia or an EndOfLineTrivia is dead -- either
//     superseded by a later indent run (exactly the adjacency pass 1 can
//     produce) or trailing indentation on what's now a blank line -- so only
//     the whitespace immediately preceding real content survives.
//  3. Cap each contiguous run of EndOfLineTrivia at 1, so a removed
//     multi-line comment block collapses to at most one blank line rather
//     than a matching run of them. The newline terminating the *previous*
//     real line already lives in that line's own last token's trailing
//     trivia (Roslyn convention: trailing trivia runs up through the first
//     EndOfLineTrivia, at most one), so this list's own leading trivia only
//     ever needs to contribute the newline for one further, intentional
//     blank line -- capping it at 1 here, not 2, is what keeps the combined
//     result (this list appended after the previous token's trailing
//     trivia) at exactly one blank line instead of two.
sealed class CommentStripper : CSharpSyntaxRewriter
{
    public override SyntaxToken VisitToken(SyntaxToken token) =>
        token.WithLeadingTrivia(Filter(token.LeadingTrivia)).WithTrailingTrivia(Filter(token.TrailingTrivia));

    private static readonly SyntaxKind[] CommentKinds =
    [
        SyntaxKind.SingleLineCommentTrivia,
        SyntaxKind.MultiLineCommentTrivia,
        SyntaxKind.SingleLineDocumentationCommentTrivia,
        SyntaxKind.MultiLineDocumentationCommentTrivia,
    ];

    private static SyntaxTriviaList Filter(SyntaxTriviaList trivia)
    {
        var noComments = trivia.Where(t => !CommentKinds.Contains(t.Kind())).ToList();

        var noDeadWhitespace = new List<SyntaxTrivia>();
        for (var i = 0; i < noComments.Count; i++)
        {
            var t = noComments[i];
            if (t.IsKind(SyntaxKind.WhitespaceTrivia) && i + 1 < noComments.Count)
            {
                var next = noComments[i + 1];
                if (next.IsKind(SyntaxKind.WhitespaceTrivia) || next.IsKind(SyntaxKind.EndOfLineTrivia)) continue;
            }
            noDeadWhitespace.Add(t);
        }

        var capped = new List<SyntaxTrivia>();
        var consecutiveNewlines = 0;
        foreach (var t in noDeadWhitespace)
        {
            if (t.IsKind(SyntaxKind.EndOfLineTrivia))
            {
                consecutiveNewlines++;
                if (consecutiveNewlines > 1) continue;
            }
            else
            {
                consecutiveNewlines = 0;
            }
            capped.Add(t);
        }
        return SyntaxFactory.TriviaList(capped);
    }
}
