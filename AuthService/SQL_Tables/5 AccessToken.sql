USE [test_db]
GO

/****** Object:  Table [dbo].[AccessToken]    Script Date: 1/12/2024 10:36:04 AM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[AccessToken](
	[TokenID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [varchar](50) NOT NULL,
	[TokenGUID] [varchar](100) NOT NULL,
	[Token] [varchar](500) NOT NULL,
	[DateTokenRequested] [date] NOT NULL,
	[Revoked] [bit] NOT NULL,
	[KeepAlive] [bit] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[TokenID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[AccessToken]  WITH CHECK ADD FOREIGN KEY([UserID])
REFERENCES [dbo].[AccountInfo] ([UserID])
GO


