# -*- coding: UTF-8 -*-
import re
import sys
from functools import reduce
from difflib import SequenceMatcher

sys.dont_write_bytecode = True

DYNAMICITY_BOUNDARY_LENGTH = 20
UPPER_RATIO_BOUND = 0.98
# 页面差异度，决定了是否确认存在注入
DIFF_TOLERANCE = 0.03

# 判断相似度
def compartion(cont1,cont2):
    """
    页面相似度检测
    """
    seqMatcher = SequenceMatcher(None)
    seqMatcher.set_seq1(cont1)
    seqMatcher.set_seq2(cont2)
    ratio = seqMatcher.quick_ratio()
    return ratio

# 查找两个页面的动态内容并标记
def findDynamicContent(firstPage, secondPage):
    """
    This function checks if the provided pages have dynamic content. If they
    are dynamic, proper markings will be made

    >>> findDynamicContent("Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.", "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.")
    >>> kb.dynamicMarkings
    [('natum reque et per. ', 'Facer tritani repreh')]
    """

    if not firstPage or not secondPage:
        return

    blocks = SequenceMatcher(None, firstPage, secondPage).get_matching_blocks()
    dynamicMarkings = []

    # Removing too small matching blocks
    for block in blocks[:]:
        (_, _, length) = block

        if length <= 2 * DYNAMICITY_BOUNDARY_LENGTH:
            blocks.remove(block)

    # Making of dynamic markings based on prefix/suffix principle
    if len(blocks) > 0:
        blocks.insert(0, None)
        blocks.append(None)

        for i in range(len(blocks) - 1):
            prefix = firstPage[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
            suffix = firstPage[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if suffix is None and (blocks[i][0] + blocks[i][2] >= len(firstPage)):
                continue

            if prefix and suffix:
                prefix = prefix[-DYNAMICITY_BOUNDARY_LENGTH:]
                suffix = suffix[:DYNAMICITY_BOUNDARY_LENGTH]

                infix = max(re.search(r"(?s)%s(.+)%s" % (re.escape(prefix), re.escape(suffix)), _) for _ in (firstPage, secondPage)).group(1)

                if infix[0].isalnum():
                    prefix = trimAlphaNum(prefix)

                if infix[-1].isalnum():
                    suffix = trimAlphaNum(suffix)

            dynamicMarkings.append((prefix if prefix else None, suffix if suffix else None))
    return dynamicMarkings

def trimAlphaNum(value):
    """
    Trims alpha numeric characters from start and ending of a given value

    >>> trimAlphaNum(u'AND 1>(2+3)-- foobar')
    u' 1>(2+3)-- '
    """

    while value and value[-1].isalnum():
        value = value[:-1]

    while value and value[0].isalnum():
        value = value[1:]

    return value

# 去除动态内容
def removeDynamicContent(page, dynamicMarkings):
    """
    Removing dynamic content from supplied page basing removal on
    precalculated dynamic markings
    """
    if dynamicMarkings == []:
        return page
    if page:
        page =str(page)
        for item in dynamicMarkings:
            prefix, suffix = item
            prefix = str(prefix)
            suffix = str(suffix)
            if prefix is None and suffix is None:
                continue
            elif prefix is None:
                page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), bytes.decode(page))
            elif suffix is None:
                page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), bytes.decode(page))
            else:
                page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)), "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), bytes.decode(page))

    return str.encode(str(page))

# 去除所有标签、js代码、css代码
def getFilteredPageContent(page, payload, onlyText=True, split=b" "):
    """
    Returns filtered page content without script, style and/or comments
    or all HTML tags

    >>> getFilteredPageContent(b'<html><title>foobar</title><body>test</body></html>')
    b'foobar test'

    ----page: r.content
    ----onlyText: unknown
    ----split: 替换符
    """

    retVal = page

    # only if the page's charset has been successfully identified
    if isinstance(page, bytes):
        retVal = re.sub(b"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (b"|<[^>]+>|\t|\n|\r" if onlyText else b""), split, page)
        retVal = re.sub(b"%s{2,}" % split, split, retVal)
        retVal = htmlunescape(retVal.strip().strip(split), payload)

    return retVal

def htmlunescape(value, payload):
    """
    Returns (basic conversion) HTML unescaped value

    >>> htmlunescape(b'a&lt;b')
    b'a<b'
    """

    retVal = value
    if value and isinstance(value, bytes):
        codes = ((b"&lt;", b'<'), (b"&gt;", b'>'), (b"&quot;", b'"'), (b"&nbsp;", b' '), (b"&amp;", b'&'), (b"&apos;", b"'"))
        retVal = reduce(lambda x, y: x.replace(y[0], y[1]), codes, retVal)
        retVal = keywordreplace(retVal, payload)
    return retVal

def keywordreplace(value, payload):
    '''
    Replace the injection statement with 'REFLECTED_VALUE'

    >>> keywordreplace('id=1 AND 1=1')
    b'id=1REPLACE_VALUE'
    '''

    retVal = value
    if value and isinstance(value, bytes):
        if payload and payload in retVal:
            retVal = retVal.replace(payload, b'REFLECTED_VALUE')
    return retVal