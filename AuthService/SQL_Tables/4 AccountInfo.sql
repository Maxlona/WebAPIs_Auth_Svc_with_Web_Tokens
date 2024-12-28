USE [test_db]
GO

/****** Object:  Table [dbo].[AccountInfo]    Script Date: 1/12/2024 10:36:18 AM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[AccountInfo](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [varchar](50) NOT NULL,
	[FirstName] [varchar](50) NULL,
	[LastName] [varchar](50) NULL,
	[UserName] [varchar](50) NULL,
	[Email] [varchar](100) NULL,
	[AccountType] [int] NOT NULL,
	[AccountStatus] [int] NOT NULL,
	[BackupEmail] [varchar](100) NULL,
	[DOB] [date] NULL,
	[VerifyCodeID] [int] NULL,
	[Password] [varchar](1000) NOT NULL,
	[Phone] [varchar](10) NULL,
	[profileImageUrl] [varchar](1000) NULL,
	[City] [varchar](100) NULL,
	[State] [varchar](50) NULL,
	[Zip] [varchar](10) NULL,
	[Joined] [date] NULL,
PRIMARY KEY CLUSTERED 
(
	[UserID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
UNIQUE NONCLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[AccountInfo]  WITH CHECK ADD FOREIGN KEY([AccountStatus])
REFERENCES [dbo].[AccountStatus] ([ID])
GO

ALTER TABLE [dbo].[AccountInfo]  WITH CHECK ADD FOREIGN KEY([AccountType])
REFERENCES [dbo].[AccountTypes] ([ID])
GO


