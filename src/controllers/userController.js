import { StatusCodes } from 'http-status-codes'
import ms from 'ms'
import {
  JwtProvider,
  ACCESS_TOKEN_SECRET_SIGNATURE,
  REFRESH_TOKEN_SECRET_SIGNATURE
} from '~/providers/JwtProvider'

/**
 * Mock nhanh thông tin user thay vì phải tạo Database rồi query.
 */
const MOCK_DATABASE = {
  USER: {
    ID: 'trantungdev-sample-id-12345678',
    EMAIL: 'trantungdev3105@gmail.com',
    PASSWORD: 'trantungdev@3105'
  }
}

const login = async (req, res) => {
  try {
    if (req.body.email !== MOCK_DATABASE.USER.EMAIL || req.body.password !== MOCK_DATABASE.USER.PASSWORD) {
      res.status(StatusCodes.FORBIDDEN).json({ message: 'Your email or password is incorrect!' })
      return
    }

    // Trường hợp nhập đúng thông tin tài khoản, tạo token và trả về cho phía Client
    const userInfo = {
      id: MOCK_DATABASE.USER.ID,
      email: MOCK_DATABASE.USER.EMAIL
    }

    const accessToken = await JwtProvider.generateToken(userInfo, ACCESS_TOKEN_SECRET_SIGNATURE, '1h')

    const refreshToken = await JwtProvider.generateToken(userInfo, REFRESH_TOKEN_SECRET_SIGNATURE, '14 days')

    // Lưu thông tin token vào cookie
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: ms('14 days')
    })

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: ms('14 days')
    })

    res.status(StatusCodes.OK).json({
      ...userInfo,
      accessToken,
      refreshToken
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    res.clearCookie('accessToken')
    res.clearCookie('refreshToken')

    res.status(StatusCodes.OK).json({ message: 'Logout API success!' })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const refreshToken = async (req, res) => {
  try {
    // Cách 1: Lấy luôn Cookie đã đính kèm vào request
    const refreshTokenFromCookie = req.cookies?.refreshToken

    // Cách 2: Từ localstorage phía FE sẽ truyền vào body khi gọi API
    const refreshTokenFromBody = req.body?.refreshToken

    // Verify / Giải mã token xem có hợp lệ không
    const refreshTokenDecoded = await JwtProvider.verifyToken(
      refreshTokenFromBody,
      REFRESH_TOKEN_SECRET_SIGNATURE
    )

    // Đoạn này vì chỉ lưu thông tin unique và cố định của user trong token rồi, vì vậy có thể lấy luôn decoded ra, tiết kiệm query vào DB để lấy data mới
    const userInfo = {
      id: refreshTokenDecoded?.id,
      email: refreshTokenDecoded?.email
    }

    // Tạo accessToken mới
    const accessToken = await JwtProvider.generateToken(userInfo, ACCESS_TOKEN_SECRET_SIGNATURE, '1h')

    // Res lại cookie accessToken mới cho trường hợp sử dụng cookie
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: ms('14 days')
    })

    // Trả về accessToken mới cho trường hợp FE cần update lại trong localstorage
    res.status(StatusCodes.OK).json({ accessToken })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Refresh Token api error!' })
  }
}

export const userController = {
  login,
  logout,
  refreshToken
}
