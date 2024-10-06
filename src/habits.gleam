import gleam/dynamic
import gleam/int
import gleam/json
import gleam/list
import lustre
import lustre/attribute as attr
import lustre/effect
import lustre/element
import lustre/element/html.{div, text}
import lustre/event
import lustre_http.{type HttpError}
import plinth/javascript/storage

pub type Flags {
  Flags(api_url: String)
}

pub type Model {
  Model(auth: Auth, login_form: LoginForm, flags: Flags, notices: List(Notice))
}

fn new_model() -> Model {
  Model(
    auth: Unauthenticated,
    flags: Flags(api_url: "https://123.supabase.co"),
    login_form: new_login_form(),
    notices: [],
  )
}

pub type Auth {
  Unauthenticated
  Authenticated(data: AuthData)
}

pub type LoginForm {
  LoginForm(email: String, password: String)
}

pub fn new_login_form() -> LoginForm {
  LoginForm(email: "", password: "")
}

pub type Notice {
  Notice(message: String)
}

fn init(_flags) -> #(Model, effect.Effect(Msg)) {
  #(new_model(), effect.none())
}

pub type Msg {
  ApiReturnedAuthData(Result(AuthData, HttpError))
  ClickedLogin
  ChangedEmail(String)
  ChangedPassword(String)
}

type Returns =
  #(Model, effect.Effect(Msg))

pub fn main() {
  let app = lustre.application(init, update, view)
  let assert Ok(_) = lustre.start(app, "#app", Nil)

  Nil
}

pub fn update(model: Model, msg: Msg) -> #(Model, effect.Effect(Msg)) {
  case msg {
    ApiReturnedAuthData(result) -> on_api_returned_auth_data(model, result)
    ChangedEmail(email) -> #(
      Model(..model, login_form: LoginForm(..model.login_form, email: email)),
      effect.none(),
    )
    ChangedPassword(password) -> #(
      Model(
        ..model,
        login_form: LoginForm(..model.login_form, password: password),
      ),
      effect.none(),
    )
    ClickedLogin -> #(model, effect.none())
  }
}

fn on_api_returned_auth_data(
  model: Model,
  result: Result(AuthData, HttpError),
) -> Returns {
  case result {
    // TODO Store data in LocalStorage
    Ok(data) -> #(Model(..model, auth: Authenticated(data)), effect.none())
    Error(error) -> #(
      Model(..model, notices: [Notice(http_error_to_string(error))]),
      effect.none(),
    )
  }
}

fn login(model: Model) -> effect.Effect(Msg) {
  let expect = lustre_http.expect_json(auth_data_decoder(), ApiReturnedAuthData)

  let payload =
    json.object([
      #("email", json.string(model.login_form.email)),
      #("password", json.string(model.login_form.password)),
    ])

  lustre_http.post(model.flags.api_url <> "/auth/v1/login", payload, expect)
}

/// Decoders
pub type AuthData {
  AuthData(
    access_token: String,
    refresh_token: String,
    expires_at: Int,
    user: User,
  )
}

pub type User {
  User(id: String, email: String)
}

pub fn auth_data_decoder() {
  dynamic.decode4(
    AuthData,
    dynamic.field("access_token", dynamic.string),
    dynamic.field("refresh_token", dynamic.string),
    dynamic.field("expires_at", dynamic.int),
    dynamic.field("user", login_user_decoder()),
  )
}

pub fn login_user_decoder() {
  dynamic.decode2(
    User,
    dynamic.field("id", dynamic.string),
    dynamic.field("email", dynamic.string),
  )
}

/// Views
pub fn view(model: Model) -> element.Element(Msg) {
  html.div([], [view_login(model)])
}

fn view_login(model: Model) {
  html.form([event.on_submit(ClickedLogin)], [
    div([], [
      html.label([], [text("Email")]),
      html.input([attr.type_("text"), attr.value(model.login_form.email)]),
    ]),
    div([], [
      html.label([], [text("Passsword")]),
      html.input([attr.type_("password"), attr.value(model.login_form.password)]),
    ]),
    div([], [html.input([attr.type_("submit"), attr.value("Login")])]),
  ])
}

/// Helpers
fn http_error_to_string(error: HttpError) -> String {
  case error {
    lustre_http.BadUrl(str) -> "BadUrl " <> str
    lustre_http.InternalServerError(str) -> "InternalServerError " <> str
    lustre_http.JsonError(err) -> json_error_to_string(err)
    lustre_http.NetworkError -> "NetworkError"
    lustre_http.NotFound -> "NotFound"
    lustre_http.OtherError(_code, str) -> "OtherError " <> str
    lustre_http.Unauthorized -> "Unauthorized"
  }
}

fn json_error_to_string(error: json.DecodeError) -> String {
  case error {
    json.UnexpectedEndOfInput -> "UnexpectedEndOfInput"
    json.UnexpectedByte(_, _) -> "UnexpectedByte"
    json.UnexpectedSequence(_, _) -> "UnexpectedSequence"
    json.UnexpectedFormat(_) -> "UnexpectedFormat"
  }
}
