import { StatusCodes } from 'http-status-codes'

const access = async (req, res) => {
  try {
    // const user = { email: 'trantungdev3105@gmail.com' }
    const user = {
      id: req?.jwtDecoded?.id,
      email: req?.jwtDecoded?.email
    }

    res.status(StatusCodes.OK).json(user)
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const dashboardController = {
  access
}
