import gleroglero/mini
import lustre/attribute.{class}
import lustre/element/html

pub type Icon {
  Archive
  Clear
  Check
  ChevronDown
  ChevronLeft
  ChevronRight
  ChevronUp
  Plus
  Trash
  Unarchive
}

pub fn icon(icon icon: Icon) {
  let svg = case icon {
    Archive -> mini.archive_box_arrow_down()
    Check -> mini.check()
    ChevronDown -> mini.chevron_down()
    ChevronLeft -> mini.chevron_left()
    ChevronRight -> mini.chevron_right()
    ChevronUp -> mini.chevron_up()
    Clear -> mini.x_mark()
    Plus -> mini.plus()
    Trash -> mini.trash()
    Unarchive -> mini.archive_box_x_mark()
  }

  html.span([class("h-6 w-6 block")], [svg])
}
