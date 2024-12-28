USE [test_db]
GO

/****** Object:  Table [dbo].[VerifyCodes]    Script Date: 1/12/2024 10:36:38 AM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[VerifyCodes](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [varchar](50) NULL,
	[Code] [varchar](100) NOT NULL,
	[VerifyType] [int] NOT NULL,
	[VerifyDate] [date] NULL,
	[CreationDate] [date] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[VerifyCodes]  WITH CHECK ADD FOREIGN KEY([UserID])
REFERENCES [dbo].[AccountInfo] ([UserID])
GO


