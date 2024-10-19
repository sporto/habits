pub type RemoteData(data) {
  RemoteDataNotAsked
  RemoteDataLoading
  RemoteDataFailure(String)
  RemoteDataSuccess(data)
}

pub fn map(data: RemoteData(a), fun: fn(a) -> b) -> RemoteData(b) {
  case data {
    RemoteDataNotAsked -> RemoteDataNotAsked
    RemoteDataLoading -> RemoteDataLoading
    RemoteDataFailure(e) -> RemoteDataFailure(e)
    RemoteDataSuccess(data) -> RemoteDataSuccess(fun(data))
  }
}
