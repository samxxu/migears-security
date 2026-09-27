<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\Sanitizer;

class SanitizerTest extends TestCase
{
    // --- escape ---

    public function testEscapeConvertsHtmlSpecialChars(): void
    {
        $result = Sanitizer::escape('<script>alert("xss")</script>');
        $this->assertStringContainsString('&lt;script&gt;', $result);
        $this->assertStringContainsString('&quot;xss&quot;', $result);
        $this->assertStringNotContainsString('<script>', $result);
    }

    public function testEscapeEmptyString(): void
    {
        $this->assertSame('', Sanitizer::escape(''));
    }

    public function testEscapeSafeStringUnchanged(): void
    {
        $this->assertSame('Hello World 123', Sanitizer::escape('Hello World 123'));
    }

    // --- stripTags ---

    public function testStripTagsRemovesAllHtml(): void
    {
        $result = Sanitizer::stripTags('<p>Hello <b>World</b></p>');
        $this->assertSame('Hello World', $result);
    }

    public function testStripTagsAllowsSpecifiedTags(): void
    {
        $result = Sanitizer::stripTags('<p>Hello <b>World</b></p>', '<p>');
        $this->assertSame('<p>Hello World</p>', $result);
    }

    public function testStripTagsDropsJavascriptHrefOnAllowedTag(): void
    {
        $result = Sanitizer::stripTags('<a href="javascript:alert(1)">click</a>', '<a>');
        $this->assertSame('<a>click</a>', $result);
    }

    public function testStripTagsDropsEventHandlerAttributes(): void
    {
        $this->assertSame('<p>hi</p>', Sanitizer::stripTags('<p onclick="steal()">hi</p>', '<p>'));
        // src is a harmless relative URL and is kept; the handler is dropped
        $this->assertSame('<img src="x">', Sanitizer::stripTags('<img src=x onerror=alert(1)>', '<img>'));
    }

    public function testStripTagsDropsStyleAndUnknownAttributes(): void
    {
        $this->assertSame('<p>hi</p>', Sanitizer::stripTags('<p align="center" style="color:red">hi</p>', '<p>'));
    }

    public function testStripTagsKeepsSafeAttributes(): void
    {
        $result = Sanitizer::stripTags('<a href="https://ok.example" title="ok">y</a>', '<a>');
        $this->assertSame('<a href="https://ok.example" title="ok">y</a>', $result);
    }

    public function testStripTagsKeepsRelativeUrls(): void
    {
        $result = Sanitizer::stripTags('<a href="/local/path?a=1&amp;b=2">y</a>', '<a>');
        $this->assertSame('<a href="/local/path?a=1&amp;b=2">y</a>', $result);
    }

    public function testStripTagsRejectsEncodedJavascriptScheme(): void
    {
        $this->assertSame('<a>y</a>', Sanitizer::stripTags('<a href="java&#115;cript:alert(1)">y</a>', '<a>'));
        $this->assertSame('<a>y</a>', Sanitizer::stripTags("<a href=\"java\nscript:alert(1)\">y</a>", '<a>'));
    }

    public function testStripTagsRejectsDataAndVbscriptSchemes(): void
    {
        $this->assertSame('<img>', Sanitizer::stripTags('<img src="data:text/html;base64,PHN2Zz4=">', '<img>'));
        $this->assertSame('<a>y</a>', Sanitizer::stripTags('<a href="vbscript:msgbox(1)">y</a>', '<a>'));
    }

    public function testStripTagsDropsSrcdocOnAllowedTag(): void
    {
        $this->assertSame('<iframe>x</iframe>', Sanitizer::stripTags('<iframe srcdoc="alert(1)">x</iframe>', '<iframe>'));
    }

    public function testStripTagsEscapesKeptAttributeValues(): void
    {
        // A quote smuggled into a value must not break out of the attribute
        $result = Sanitizer::stripTags('<a href="/x" title=&#34;onmouseover=alert(1)&#34;>y</a>', '<a>');
        $this->assertSame('<a href="/x" title="&quot;onmouseover=alert(1)&quot;">y</a>', $result);
    }

    // --- email ---

    public function testEmailValid(): void
    {
        $this->assertSame('user@example.com', Sanitizer::email('user@example.com'));
    }

    public function testEmailRemovesIllegalChars(): void
    {
        $this->assertSame('user@example.com', Sanitizer::email("u\x00ser@example.com"));
    }

    public function testEmailInvalidReturnsNull(): void
    {
        $this->assertNull(Sanitizer::email('not-an-email'));
        $this->assertNull(Sanitizer::email(''));
    }

    // --- url ---

    public function testUrlValidHttp(): void
    {
        $this->assertSame('https://example.com/path', Sanitizer::url('https://example.com/path'));
    }

    public function testUrlInvalidReturnsNull(): void
    {
        $this->assertNull(Sanitizer::url('not a url'));
        $this->assertNull(Sanitizer::url(''));
    }

    public function testUrlJavascriptSchemeRejected(): void
    {
        $result = Sanitizer::url('javascript:alert(1)');
        $this->assertNull($result);
    }

    // --- int ---

    public function testIntWithInteger(): void
    {
        $this->assertSame(42, Sanitizer::int(42));
    }

    public function testIntWithNumericString(): void
    {
        $this->assertSame(42, Sanitizer::int('42'));
    }

    public function testIntWithNegative(): void
    {
        $this->assertSame(-5, Sanitizer::int('-5'));
    }

    public function testIntInvalidReturnsNull(): void
    {
        $this->assertNull(Sanitizer::int('abc'));
        $this->assertNull(Sanitizer::int('3.14'));
        $this->assertNull(Sanitizer::int(null));
    }

    // --- float ---

    public function testFloatWithFloat(): void
    {
        $this->assertSame(3.14, Sanitizer::float(3.14));
    }

    public function testFloatWithNumericString(): void
    {
        $this->assertSame(3.14, Sanitizer::float('3.14'));
    }

    public function testFloatInvalidReturnsNull(): void
    {
        $this->assertNull(Sanitizer::float('abc'));
        $this->assertNull(Sanitizer::float(null));
    }

    // --- string ---

    public function testStringTrimsAndRemovesControlChars(): void
    {
        $result = Sanitizer::string("  hello\x00\x01world  ");
        $this->assertSame('helloworld', $result);
    }

    public function testStringPreservesNewlinesAndTabs(): void
    {
        $result = Sanitizer::string("hello\tworld\n");
        $this->assertSame("hello\tworld", trim($result, "\n"));
    }

    // --- plainText ---

    public function testPlainTextStripsTagsAndDecodes(): void
    {
        $result = Sanitizer::plainText('<p>Hello &amp; <b>World</b></p>');
        $this->assertSame('Hello & World', $result);
    }

    public function testPlainTextCollapsesWhitespace(): void
    {
        $result = Sanitizer::plainText("hello    world\n\nfoo");
        $this->assertSame('hello world foo', $result);
    }

    // --- filename ---

    public function testFilenameRemovesPathTraversal(): void
    {
        $result = Sanitizer::filename('../../etc/passwd');
        $this->assertSame('passwd', $result);
    }

    public function testFilenameRemovesNullBytes(): void
    {
        $result = Sanitizer::filename("file\x00.txt");
        $this->assertSame('file.txt', $result);
    }

    public function testFilenameNormalNameUnchanged(): void
    {
        $this->assertSame('document.pdf', Sanitizer::filename('document.pdf'));
    }

    public function testFilenameStripsWindowsPathTraversal(): void
    {
        $this->assertSame('cmd.exe', Sanitizer::filename('..\\..\\windows\\system32\\cmd.exe'));
    }

    public function testFilenameRejectsDotSegments(): void
    {
        $this->assertSame('', Sanitizer::filename('..'));
        $this->assertSame('', Sanitizer::filename('.'));
        $this->assertSame('', Sanitizer::filename('dir/..'));
    }

    public function testFilenameTrimsSurroundingWhitespace(): void
    {
        $this->assertSame('spaced.txt', Sanitizer::filename("  spaced.txt  "));
    }

    public function testFilenameKeepsInnerDots(): void
    {
        $this->assertSame('archive.tar.gz', Sanitizer::filename('archive.tar.gz'));
        $this->assertSame('...', Sanitizer::filename('...'));
    }

    public function testFilenameEmptyInputReturnsEmptyString(): void
    {
        $this->assertSame('', Sanitizer::filename(''));
        $this->assertSame('', Sanitizer::filename('/'));
    }

    // --- hasXssRisk ---

    public function testHasXssRiskScriptTag(): void
    {
        $this->assertTrue(Sanitizer::hasXssRisk('<script>alert(1)</script>'));
    }

    public function testHasXssRiskJavascriptProtocol(): void
    {
        $this->assertTrue(Sanitizer::hasXssRisk('<a href="javascript:alert(1)">'));
    }

    public function testHasXssRiskEventHandler(): void
    {
        $this->assertTrue(Sanitizer::hasXssRisk('<div onclick="alert(1)">'));
    }

    public function testHasXssRiskIframe(): void
    {
        $this->assertTrue(Sanitizer::hasXssRisk('<iframe src="evil.com">'));
    }

    public function testHasXssRiskSafeString(): void
    {
        $this->assertFalse(Sanitizer::hasXssRisk('Hello, world!'));
        $this->assertFalse(Sanitizer::hasXssRisk('<p>Safe paragraph</p>'));
    }

    public function testHasXssRiskCaseInsensitive(): void
    {
        $this->assertTrue(Sanitizer::hasXssRisk('<SCRIPT>alert(1)</SCRIPT>'));
    }
}
