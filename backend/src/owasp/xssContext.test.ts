import { describe, expect, it } from 'vitest'
import { reflectionContext } from './activeChecks'

const NEEDLE = '<svg/onload=rxss9842>'

describe('reflectionContext', () => {
  it('classifies an unencoded reflection in HTML text as executable', () => {
    expect(reflectionContext(`<div>hello ${NEEDLE} world</div>`, NEEDLE)).toBe('html')
  })

  it('downgrades a reflection inside <script> (JS text)', () => {
    expect(reflectionContext(`<script>var a = "${NEEDLE}";</script>`, NEEDLE)).toBe('script')
  })

  it('downgrades a reflection inside an HTML comment', () => {
    expect(reflectionContext(`<!-- debug: ${NEEDLE} -->`, NEEDLE)).toBe('comment')
  })

  it('downgrades a reflection inside a <textarea> (RCDATA)', () => {
    expect(reflectionContext(`<textarea>${NEEDLE}</textarea>`, NEEDLE)).toBe('rcdata')
  })

  it('treats a reflection AFTER a closed script/comment as HTML again', () => {
    expect(reflectionContext(`<script>x=1</script><div>${NEEDLE}</div>`, NEEDLE)).toBe('html')
    expect(reflectionContext(`<!-- a --> ${NEEDLE}`, NEEDLE)).toBe('html')
  })
})
