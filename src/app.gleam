import birl.{type Day}
import gleam/dynamic
import gleam/http.{type Method, Get, Https, Post}
import gleam/http/request.{type Request}
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result.{try}
import lib/return
import lustre
import lustre/attribute.{class} as attr
import lustre/effect
import lustre/element.{type Element}
import lustre/element/html.{div, text}
import lustre/event
import lustre_http.{type HttpError}
import plinth/javascript/storage

pub type Flags {
  Flags(api_host: String, api_public_key: String)
}

pub type Model {
  Model(
    auth: Auth,
    // checks: RemoteData(List(Check)),
    flags: Flags,
    habits: RemoteData(List(Habit)),
    is_adding: Bool,
    login_form: LoginForm,
    new_habit_form: NewHabitForm,
    notices: List(Notice),
  )
}

fn new_model(flags: Flags) -> Model {
  Model(
    auth: Unauthenticated,
    // checks: RemoteDataNotAsked,
    flags:,
    habits: RemoteDataNotAsked,
    is_adding: False,
    login_form: new_login_form(),
    new_habit_form: new_habit_form(),
    notices: [],
  )
}

pub type RemoteData(data) {
  RemoteDataNotAsked
  RemoteDataLoading
  RemoteDataSuccess(data)
  RemoteDataFailure(String)
}

pub type Auth {
  Unauthenticated
  Authenticated(data: SessionData)
}

pub type LoginForm {
  LoginForm(email: String, password: String)
}

pub fn new_login_form() -> LoginForm {
  LoginForm(email: "", password: "")
}

pub type NewHabitForm {
  NewHabitForm(label: String)
}

fn new_habit_form() -> NewHabitForm {
  NewHabitForm(label: "")
}

pub type Notice {
  Notice(message: String)
}

pub type HabitCollection {
  HabitCollection(date: Day, habits: List(Habit))
}

pub type Habit {
  Habit(id: String, label: String)
}

// pub type CheckCollection

fn habit_decoder() {
  dynamic.decode2(
    Habit,
    dynamic.field("id", dynamic.string),
    dynamic.field("label", dynamic.string),
  )
}

fn habits_decoder() {
  dynamic.list(habit_decoder())
}

fn init(flags: Flags) -> #(Model, effect.Effect(Msg)) {
  // io.debug(flags)
  #(new_model(flags), get_session())
}

pub type Msg {
  UnauthenticatedMsg(UnauthenticatedMsg)
  AuthenticatedMsg(SessionData, AuthenticatedMsg)
}

pub type UnauthenticatedMsg {
  ApiReturnedSessionData(Result(SessionData, HttpError))
  ClickedLogin
  ChangedEmail(String)
  ChangedPassword(String)
  GotSessionDataFromLS(SessionData)
}

pub type AuthenticatedMsg {
  ApiCreatedHabit(Result(Nil, HttpError))
  ApiReturnedHabits(Result(List(Habit), HttpError))
  NewHabitLabelChanged(String)
  NewHabitFormSubmitted
}

type Returns =
  #(Model, effect.Effect(Msg))

pub fn main(flags: dynamic.Dynamic) {
  let app = lustre.application(init, update, view)
  let assert Ok(flags) = flags_decoder()(flags)
  let assert Ok(_) = lustre.start(app, "#app", flags)

  Nil
}

pub fn update(model: Model, msg: Msg) -> Returns {
  case msg {
    UnauthenticatedMsg(unauth_msg) -> update_unauthenticated(model, unauth_msg)
    AuthenticatedMsg(session, auth_msg) ->
      update_authenticated(session, model, auth_msg)
  }
}

pub fn update_unauthenticated(model: Model, msg: UnauthenticatedMsg) -> Returns {
  case msg {
    ApiReturnedSessionData(result) -> on_api_returned_auth_data(model, result)

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
    ClickedLogin -> {
      io.debug("Clicked login")
      #(model, login(model))
    }
    GotSessionDataFromLS(session) -> {
      #(Model(..model, auth: Authenticated(session)), effect.none())
      |> return.then(fetch_today_habits(_, session))
    }
  }
}

pub fn update_authenticated(
  session: SessionData,
  model: Model,
  msg: AuthenticatedMsg,
) -> Returns {
  case msg {
    ApiReturnedHabits(result) -> {
      case result {
        Ok(habits) -> {
          #(Model(..model, habits: RemoteDataSuccess(habits)), effect.none())
        }
        Error(error) -> {
          io.debug(error)
          #(
            Model(
              ..model,
              habits: RemoteDataFailure(http_error_to_string(error)),
            ),
            effect.none(),
          )
        }
      }
    }
    ApiCreatedHabit(_result) -> {
      #(
        Model(..model, new_habit_form: new_habit_form(), is_adding: False),
        effect.none(),
      )
      |> return.then(fetch_today_habits(_, session))
    }
    NewHabitLabelChanged(label) -> #(
      Model(..model, new_habit_form: NewHabitForm(label: label)),
      effect.none(),
    )
    NewHabitFormSubmitted -> {
      #(
        Model(..model, is_adding: True),
        create_habit(model, session) |> effect.map(AuthenticatedMsg(session, _)),
      )
    }
  }
}

fn on_api_returned_auth_data(
  model: Model,
  result: Result(SessionData, HttpError),
) -> Returns {
  case result {
    Ok(data) -> #(
      Model(..model, auth: Authenticated(data)),
      store_session(data),
    )
    Error(error) -> #(
      Model(..model, notices: [Notice(http_error_to_string(error))]),
      effect.none(),
    )
  }
}

fn login(model: Model) -> effect.Effect(Msg) {
  let expect =
    lustre_http.expect_json(session_data_decoder(), ApiReturnedSessionData)

  let payload =
    json.object([
      #("email", json.string(model.login_form.email)),
      #("password", json.string(model.login_form.password)),
    ])

  // let url = api_login_url(model.flags)

  io.debug(payload)

  build_api_request(
    flags: model.flags,
    method: Post,
    path: "/auth/v1/token",
    query: [#("grant_type", "password")],
    payload: Some(payload),
  )
  |> lustre_http.send(expect)
  |> effect.map(UnauthenticatedMsg)
}

fn get_session() -> effect.Effect(Msg) {
  case get_session_do() {
    Ok(session_data) ->
      effect.from(fn(dispatch) { dispatch(GotSessionDataFromLS(session_data)) })
      |> effect.map(UnauthenticatedMsg)
    Error(err) -> {
      io.debug(err)
      effect.none()
    }
  }
}

fn get_session_do() -> Result(SessionData, String) {
  use local_storage <- try(
    storage.local()
    |> result.replace_error("Unable to open local storage"),
  )

  use json_string <- try(
    storage.get_item(local_storage, "session")
    |> result.replace_error("Unable to get session data from local storage"),
  )

  use data <- try(
    json.decode(json_string, session_data_decoder())
    |> result.map_error(json_error_to_string),
  )

  Ok(data)
}

fn store_session(data: SessionData) -> effect.Effect(Msg) {
  case store_session_do(data) {
    Ok(_) -> {
      effect.none()
    }
    Error(_) -> {
      io.debug("Failed to open local storage")
      effect.none()
    }
  }
}

fn store_session_do(data: SessionData) -> Result(Nil, String) {
  use local_storage <- try(
    storage.local()
    |> result.replace_error("Unable to open local storage"),
  )

  let json_string = session_encode(data) |> json.to_string

  storage.set_item(local_storage, "session", json_string)
  |> result.replace_error("Unable to store session data in local storage")
}

fn fetch_today_habits(model: Model, session: SessionData) -> Returns {
  fetch_habits_for_date(model, session)
}

fn fetch_habits_for_date(model: Model, session: SessionData) -> Returns {
  // TODO, add date
  let expect =
    lustre_http.expect_json(habits_decoder(), fn(result) {
      AuthenticatedMsg(session, ApiReturnedHabits(result))
    })

  let effect =
    api_crud_request(
      flags: model.flags,
      method: Get,
      path: "/habits",
      payload: None,
      query: [],
      session:,
    )
    |> lustre_http.send(expect)

  #(Model(..model, habits: RemoteDataLoading), effect)
}

fn create_habit(
  model: Model,
  session: SessionData,
) -> effect.Effect(AuthenticatedMsg) {
  let expect = lustre_http.expect_anything(ApiCreatedHabit)

  let payload =
    json.object([
      //
      // #("user_id", json.string(session.user.id)),
      #("label", json.string(model.new_habit_form.label)),
    ])

  api_crud_request(
    flags: model.flags,
    method: Post,
    path: "/habits",
    payload: Some(payload),
    query: [],
    session:,
  )
  |> lustre_http.send(expect)
}

/// Decoders
pub fn flags_decoder() {
  dynamic.decode2(
    Flags,
    dynamic.field("apiHost", dynamic.string),
    dynamic.field("apiPublicKey", dynamic.string),
  )
}

pub type SessionData {
  SessionData(
    access_token: String,
    refresh_token: String,
    expires_at: Int,
    user: User,
  )
}

pub type User {
  User(id: String, email: String)
}

pub fn session_data_decoder() {
  dynamic.decode4(
    SessionData,
    dynamic.field("access_token", dynamic.string),
    dynamic.field("refresh_token", dynamic.string),
    dynamic.field("expires_at", dynamic.int),
    dynamic.field("user", session_user_decoder()),
  )
}

pub fn session_encode(data: SessionData) {
  json.object([
    #("access_token", json.string(data.access_token)),
    #("refresh_token", json.string(data.refresh_token)),
    #("expires_at", json.int(data.expires_at)),
    #("user", session_user_encode(data.user)),
  ])
}

pub fn session_user_decoder() {
  dynamic.decode2(
    User,
    dynamic.field("id", dynamic.string),
    dynamic.field("email", dynamic.string),
  )
}

pub fn session_user_encode(user: User) {
  json.object([
    #("id", json.string(user.id)),
    #("email", json.string(user.email)),
  ])
}

/// Views
pub fn view(model: Model) -> element.Element(Msg) {
  case model.auth {
    Unauthenticated ->
      view_unauthenticated(model) |> element.map(UnauthenticatedMsg)

    Authenticated(session) -> {
      let now = birl.now() |> birl.to_unix

      case now > session.expires_at {
        True -> {
          io.debug("Session expired")
          view_unauthenticated(model) |> element.map(UnauthenticatedMsg)
        }
        False -> {
          view_authenticated(model, session)
          |> element.map(AuthenticatedMsg(session, _))
        }
      }
    }
  }
}

fn view_unauthenticated(model: Model) -> Element(UnauthenticatedMsg) {
  html.main([class("pt-4 flex justify-center")], [view_login_form(model)])
}

fn view_login_form(model: Model) {
  html.form([event.on_submit(ClickedLogin), class("space-y-4")], [
    div([], [
      html.label([class("block")], [text("Email")]),
      html.input([
        attr.type_("text"),
        attr.name("email"),
        attr.value(model.login_form.email),
        event.on_input(ChangedEmail),
      ]),
    ]),
    div([], [
      html.label([class("block")], [text("Passsword")]),
      html.input([
        attr.type_("password"),
        attr.name("password"),
        attr.value(model.login_form.password),
        event.on_input(ChangedPassword),
      ]),
    ]),
    div([], [
      html.input([
        class("border p-2"),
        attr.type_("submit"),
        attr.value("Login"),
      ]),
    ]),
  ])
}

fn view_authenticated(
  model: Model,
  session: SessionData,
) -> Element(AuthenticatedMsg) {
  html.main([], [
    view_header(model, session),
    //
    view_new_habit_form(model, session),
    view_habits(model),
  ])
}

fn view_header(model: Model, session: SessionData) {
  html.header([class("t-header p-2 bg-black text-white")], [
    text(session.user.email),
    //
  ])
}

fn view_new_habit_form(model: Model, session: SessionData) {
  html.section([class("t-new-habit-form py-3")], [
    //
    html.form(
      [
        //
        class("flex space-x-2 p-2 items-center"),
        event.on_submit(NewHabitFormSubmitted),
      ],
      [
        //
        html.label([class("")], [text("New")]),
        html.input([
          class("h-8 rounded"),
          attr.type_("text"),
          attr.name("label"),
          attr.value(model.new_habit_form.label),
          event.on_input(NewHabitLabelChanged),
        ]),
        html.input([
          class("cursor-pointer border px-2 py-1 rounded h-8"),
          attr.type_("submit"),
          attr.value("Add"),
          attr.disabled(model.is_adding),
        ]),
      ],
    ),
  ])
}

fn view_habits(model: Model) {
  case model.habits {
    RemoteDataNotAsked | RemoteDataLoading ->
      html.section([class("p-2")], [text("Loading habits...")])
    RemoteDataSuccess(habits) -> view_habits_with_data(habits)
    RemoteDataFailure(error) -> text(error)
  }
}

fn view_habits_with_data(habits: List(Habit)) {
  html.section([class("p-2")], [
    html.ul([class("t-habits-list")], list.map(habits, view_habit)),
  ])
}

fn view_habit(habit: Habit) {
  html.li([class("t-habit")], [
    html.label([class("space-x-2")], [
      html.span([], [html.input([attr.type_("checkbox"), attr.checked(False)])]),
      html.span([], [text(habit.label)]),
    ]),
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

fn build_api_request(
  flags flags: Flags,
  method method: Method,
  path path: String,
  query query: List(#(String, String)),
  payload payload: Option(json.Json),
) -> Request(String) {
  request.new()
  |> request.set_method(method)
  |> request.set_scheme(Https)
  |> request.set_host(flags.api_host)
  |> request.set_path(path)
  |> request.set_query(query)
  |> maybe_add_payload(payload)
  |> request.set_header("apikey", flags.api_public_key)
  |> request.set_header("Authorization", "Bearer " <> flags.api_public_key)
  |> request.set_header("Content-Type", "application/json")
}

fn maybe_add_payload(
  req: Request(String),
  payload: Option(json.Json),
) -> Request(String) {
  case payload {
    Some(json) -> {
      let body = json.to_string(json)
      request.set_body(req, body)
    }
    None -> req
  }
}

fn api_crud_request(
  flags flags: Flags,
  method method: Method,
  path path: String,
  payload payload: Option(json.Json),
  query query: List(#(String, String)),
  session session: SessionData,
) -> Request(String) {
  build_api_request(
    flags: flags,
    method:,
    path: "/rest/v1/" <> path,
    payload:,
    query:,
  )
  |> request.set_header("Authorization", "Bearer " <> session.access_token)
}
