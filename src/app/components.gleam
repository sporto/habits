import lustre/attribute.{class} as attr
import lustre/element/html

pub fn input(attrs) {
  html.input([class("h-12 p-2 rounded border"), ..attrs])
}

pub fn modal(children) {
  html.div(
    [
      class(
        "t-modal-backdrop fixed top-0 bottom-0 left-0 right-0 bg-slate-900/60 px-4",
      ),
    ],
    [
      html.dialog(
        [
          class("t-modal bg-white rounded p-4"),
          attr.style("margin-top", "12rem"),
          attr.attribute("open", ""),
        ],
        children,
      ),
    ],
  )
}
