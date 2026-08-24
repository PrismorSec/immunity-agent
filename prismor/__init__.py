"""Top-level Prismor package.

This file makes the source checkout a real package instead of a pure namespace
package so repo-local entry points (for example ``bin/prismor``) cannot be
shadowed by an unrelated installed ``prismor`` distribution earlier on the
import path.
"""

import pkgutil

from prismor.runtime import __version__

__path__ = pkgutil.extend_path(__path__, __name__)

__all__ = ["__version__"]
