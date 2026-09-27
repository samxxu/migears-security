<?php

declare(strict_types=1);

namespace MiGears\Security;

/**
 * Input sanitization and XSS protection utilities.
 *
 * Provides focused tools for cleaning user input before display or storage.
 * This is not a full HTML purifier — it covers the most common cases:
 * stripping tags, escaping output, and sanitizing common input types.
 *
 * Usage:
 *   echo Sanitizer::escape($userInput);           // for HTML display
 *   $clean = Sanitizer::stripTags($dirtyHtml);    // remove all HTML
 *   $email = Sanitizer::email($userEmail);        // sanitize email
 *   $url   = Sanitizer::url($userUrl);            // sanitize URL
 */
final class Sanitizer
{
    /**
     * Attributes kept on tags that survive strip_tags().
     *
     * Everything else is dropped — including every on* handler, style, srcdoc
     * and formaction — because strip_tags() keeps attributes verbatim on the
     * tags it lets through.
     *
     * @var list<string>
     */
    private const SAFE_ATTRIBUTES = ['href', 'src', 'alt', 'title', 'width', 'height'];

    /**
     * Schemes accepted in href and src attributes.
     *
     * @var list<string>
     */
    private const SAFE_SCHEMES = ['http', 'https', 'mailto', 'tel', 'ftp'];

    /**
     * Escape a string for safe HTML output.
     *
     * Use this for any user-supplied content displayed in HTML.
     * Equivalent to htmlspecialchars with strict defaults.
     */
    public static function escape(string $value, string $encoding = 'UTF-8'): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, $encoding);
    }

    /**
     * Strip all HTML and PHP tags from a string.
     *
     * When allowable tags are given, their attributes are filtered too: only
     * the attributes in SAFE_ATTRIBUTES survive, href/src must use an allowed
     * scheme, and every on* handler, style, srcdoc, and formaction is removed.
     * Without allowable tags nothing survives that could carry an attribute.
     *
     * This is still not an HTML purifier: it does not parse nesting, and output
     * escaping remains the primary defence.
     *
     * @param string $value Input string
     * @param string $allowableTags Optional list of allowed tags, e.g. '<p><a>'
     */
    public static function stripTags(string $value, string $allowableTags = ''): string
    {
        $stripped = strip_tags($value, $allowableTags);

        if ($allowableTags === '') {
            return $stripped;
        }

        return preg_replace_callback(
            '/<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/',
            static function (array $match): string {
                $attributes = '';

                if (preg_match_all(
                    '/([a-zA-Z_:][-\w:.]*)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s"\'<>`]+)/',
                    $match[2],
                    $found,
                    PREG_SET_ORDER
                )) {
                    foreach ($found as $attribute) {
                        $name = strtolower($attribute[1]);
                        // Decode first so an already-encoded value such as
                        // href="?a=1&amp;b=2" is not escaped a second time.
                        $attributeValue = html_entity_decode(
                            trim($attribute[2], '"\''),
                            ENT_QUOTES | ENT_HTML5,
                            'UTF-8'
                        );

                        if (!in_array($name, self::SAFE_ATTRIBUTES, true)) {
                            continue;
                        }

                        if (($name === 'href' || $name === 'src') && !self::isSafeUrl($attributeValue)) {
                            continue;
                        }

                        $attributes .= sprintf(' %s="%s"', $name, htmlspecialchars($attributeValue, ENT_QUOTES, 'UTF-8'));
                    }
                }

                return '<' . $match[1] . $attributes . '>';
            },
            $stripped
        ) ?? $stripped;
    }

    /**
     * Decide whether a URL attribute value can be kept.
     *
     * The scheme is read from a normalised copy — entities decoded and
     * whitespace or control characters removed — so "java&#115;cript:" and
     * "java\nscript:" are recognised as the javascript scheme.
     */
    private static function isSafeUrl(string $url): bool
    {
        $decoded = html_entity_decode($url, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $normalized = strtolower(preg_replace('/[\x00-\x20\x7F]+/', '', $decoded) ?? $decoded);

        if (preg_match('#^([a-z][a-z0-9+.\-]*):#', $normalized, $scheme)) {
            return in_array($scheme[1], self::SAFE_SCHEMES, true);
        }

        // No scheme at all: a relative URL
        return true;
    }

    /**
     * Sanitize an email address.
     *
     * Removes illegal characters and validates format.
     * Returns the sanitized email or null if invalid.
     */
    public static function email(string $value): ?string
    {
        $sanitized = filter_var($value, FILTER_SANITIZE_EMAIL);
        if ($sanitized === false || $sanitized === '') {
            return null;
        }
        if (filter_var($sanitized, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }
        return $sanitized;
    }

    /**
     * Sanitize a URL.
     *
     * Only allows http/https/ftp schemes by default.
     * Returns the sanitized URL or null if invalid.
     *
     * @param string $value URL to validate
     * @param list<string>|null $allowedSchemes Allowed scheme names without colon (e.g. ['http', 'https']).
     *                                           Default: http, https, ftp
     */
    public static function url(string $value, ?array $allowedSchemes = null): ?string
    {
        if ($allowedSchemes === null) {
            $allowedSchemes = ['http', 'https', 'ftp'];
        }
        $sanitized = filter_var($value, FILTER_SANITIZE_URL);
        if ($sanitized === false || $sanitized === '') {
            return null;
        }
        if (filter_var($sanitized, FILTER_VALIDATE_URL) === false) {
            return null;
        }
        // Validate scheme
        $scheme = strtolower(parse_url($sanitized, PHP_URL_SCHEME) ?: '');
        if (!in_array($scheme, $allowedSchemes, true)) {
            return null;
        }
        return $sanitized;
    }

    /**
     * Sanitize an integer value.
     *
     * Returns the integer value or null if not a valid integer.
     */
    public static function int(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }
        if (!is_numeric($value)) {
            return null;
        }
        $sanitized = filter_var($value, FILTER_VALIDATE_INT);
        return $sanitized === false ? null : (int) $sanitized;
    }

    /**
     * Sanitize a float value.
     */
    public static function float(mixed $value): ?float
    {
        if (is_float($value)) {
            return $value;
        }
        if (!is_numeric($value)) {
            return null;
        }
        $sanitized = filter_var($value, FILTER_VALIDATE_FLOAT);
        return $sanitized === false ? null : (float) $sanitized;
    }

    /**
     * Sanitize a string by trimming and removing control characters.
     *
     * Removes null bytes and other control characters except common whitespace.
     */
    public static function string(string $value): string
    {
        // Remove null bytes and control chars except tab, newline, carriage return
        $cleaned = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
        return trim($cleaned ?? $value);
    }

    /**
     * Remove all HTML tags and decode entities.
     *
     * Useful for extracting plain text from HTML content.
     */
    public static function plainText(string $html): string
    {
        $text = strip_tags($html);
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // Collapse whitespace
        $text = preg_replace('/\s+/', ' ', $text);
        return trim($text ?? '');
    }

    /**
     * Sanitize a filename by removing path traversal and dangerous characters.
     *
     * Both separators are treated as separators, so a traversal written for one
     * platform cannot survive on the other. A name that reduces to "." or ".."
     * is not a usable filename and returns an empty string.
     *
     * Does NOT validate that the file exists — just cleans the name string.
     */
    public static function filename(string $filename): string
    {
        // Treat Windows separators as separators everywhere
        $filename = str_replace('\\', '/', $filename);
        // Remove path traversal
        $filename = basename($filename);
        // Remove null bytes
        $filename = str_replace("\0", '', $filename);
        // Remove control characters
        $filename = preg_replace('/[\x00-\x1F\x7F]/', '', $filename) ?? $filename;
        $filename = trim($filename);

        // "." and ".." survive basename() but must never be handed back as a name
        if ($filename === '.' || $filename === '..') {
            return '';
        }

        return $filename;
    }

    /**
     * Check if a string contains potential XSS patterns.
     *
     * This is a heuristic check, not a replacement for output escaping.
     * Use it for early rejection of obviously malicious input.
     */
    public static function hasXssRisk(string $value): bool
    {
        $lower = strtolower($value);

        $patterns = [
            '/<script\b[^>]*>/i',           // <script>
            '/javascript\s*:/i',            // javascript:
            '/on\w+\s*=/i',                  // onload=, onclick=, etc.
            '/<iframe\b[^>]*>/i',           // <iframe>
            '/<object\b[^>]*>/i',           // <object>
            '/<embed\b[^>]*>/i',            // <embed>
            '/eval\s*\(/i',                  // eval(
            '/document\.cookie/i',           // document.cookie
            '/data\s*:\s*text\/html/i',      // data:text/html
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $lower)) {
                return true;
            }
        }

        return false;
    }
}
