import gleroglero/mini
import lustre/attribute.{class}
import lustre/element/html

pub type Icon {
  Archive
  Clear
  Check
  ChevronLeft
  ChevronRight
  Trash
  Unarchive
}

pub fn icon(icon icon: Icon) {
  let svg = case icon {
    Archive -> mini.archive_box_arrow_down()
    Clear -> mini.x_mark()
    Check -> mini.check()
    ChevronLeft -> mini.chevron_left()
    ChevronRight -> mini.chevron_right()
    Trash -> mini.trash()
    Unarchive -> mini.archive_box_x_mark()
  }

  html.span([class("h-6 w-6 block")], [svg])
}
