"""
Shared: the AST traversal helpers every detector needs.

All eight detectors carried a private copy of these two functions. The copies
were verified identical before extraction -- byte-for-byte in seven files, and
in the eighth (swallowed-exception) identical except for a docstring the others
lacked. No behavioral difference existed, so nothing had to be chosen between;
the more documented version is the one kept here.

Eight copies is eight places to drift. One copy is one.
"""

import ast


def link_parents(tree):
    """Give every node a `_parent` back-reference.

    `ast` does not record parents, and every detector needs to walk upward --
    to find an enclosing function, an enclosing assignment, or the call a
    keyword belongs to. Must be called once per tree before any upward walk.
    """
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._parent = parent


def enclosing_function(node):
    """Innermost enclosing def/async def name, or <module> at top level."""
    cur = getattr(node, "_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
        cur = getattr(cur, "_parent", None)
    return "<module>"
