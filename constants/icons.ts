// constants/icons.ts
import * as L from "lucide-react";
import { GoogleIcon } from "@/components/icons/google-icon";
import { FacebookIcon } from "@/components/icons/facebook-icon";

export const ICON_MAP = {
  /* Layout */
  home: L.Home,
  settings: L.Settings,
  search: L.Search,
  plus: L.Plus,
  x: L.X,
  cloud: L.Cloud,
  wifiOff: L.WifiOff,
  camera: L.Camera,
  info: L.Info,
  alertTriangle: L.AlertTriangle,
  clock: L.Clock,

  /* Socials */
  twitter: L.Twitter,
  linkedin: L.Linkedin,
  google: GoogleIcon,
  facebook: FacebookIcon,
  instagram: L.Instagram,
  youtube: L.Youtube,
  github: L.Github,
  dribbble: L.Dribbble,
  externalLink: L.ExternalLink,

  /* Notification */
  bell: L.Bell,

  /* Theme */
  sun: L.Sun,
  moon: L.Moon,

  /* UI */
  chevronRight: L.ChevronRight,
  gripVertical: L.GripVertical,
  trash: L.Trash,
  filter: L.Filter,
  bookmark: L.Bookmark,
  helpCircle: L.HelpCircle,
  heart: L.Heart,
  arrowRight: L.ArrowRight,
  menu: L.Menu,
  phone: L.Phone,
  chevronDown: L.ChevronDown,
  chevreonRight: L.ChevronRight,
  chevronLeft: L.ChevronLeft,
  chevronUp: L.ChevronUp,
  arrowLeft: L.ArrowLeft,
  arrowUp: L.ArrowUp,
  arrowDown: L.ArrowDown,

  login: L.LogIn,
  logout: L.LogOut,
  user: L.User,
  eyeOff: L.EyeOff,
  eye: L.Eye,
  mail: L.Mail,
  shieldOff: L.ShieldOff,
  shieldCheck: L.ShieldCheck,
  checkCircle: L.CheckCircle,
  heartHandshake: L.HeartHandshake,
  bookHeart: L.BookHeart,

  partyPopper: L.PartyPopper,
  holisticWorld: L.WholeWord,
  download: L.Download,
  image: L.Image,
  plusCircle: L.PlusCircle,
  piggyBank: L.PiggyBank,
  video: L.Video,
  shieldKeyhole: L.LockKeyhole,

  /* Programs */
  target: L.Target,
  trendingUp: L.TrendingUp,
  bookOpen: L.BookOpen,
  award: L.Award,
  globe: L.Globe,

  /* Finance */
  dollarSign: L.DollarSign,
  handshake: L.HandHeart,

  /* Volunteers & Users */
  users: L.Users,
  userCheck: L.UserCheck,

  /* Content */
  fileText: L.FileText,
  message: L.MessageSquare,

  /* Analytics */
  barChart3: L.BarChart3,
  activity: L.Activity,

  /* Integrations */
  zap: L.Zap,

  /* Brand */
  holistic: L.HeartHandshake,

  /* Security */
  shield: L.Shield,

  /* Calendar */
  calendar: L.Calendar,

  checkSquare: L.CheckSquare,
  square: L.Square,
  rocket: L.Rocket,
  layoutDashboard: L.LayoutDashboard,
  folder: L.Folder,
  clipboardList: L.ClipboardList,
  barChart: L.BarChart,
  ban: L.Ban,
  moreHorizontal: L.MoreHorizontal,
  lineChart: L.LineChart,
  briefcase: L.Briefcase,
  layoutGrid: L.LayoutGrid,
  barChart4: L.BarChart4,
  album: L.Album,
  banknote: L.Banknote,
  layoutTemplate: L.LayoutTemplate,
  list: L.List,
  gift: L.Gift,
  server: L.Server,
  userCog: L.UserCog,
  logOut: L.LogOut,
  monitor: L.Monitor,
  megaphone: L.Megaphone,
  filePieChart: L.FilePieChart,
  userPlus: L.UserPlus,
  edit: L.Edit,
  userCircle: L.UserCircle,
  building: L.Building,
  landmark: L.Landmark,
  slidersHorizontal: L.SlidersHorizontal,
  graduationCap: L.GraduationCap,
  loader: L.Loader,
  loader2: L.Loader2,
  messageSquareCode: L.MessageSquareCode,
  newspaper: L.Newspaper,
  grid: L.Grid,
  quote: L.Quote,
  mapPin: L.MapPin,
  alertcircle: L.AlertCircle,
  play: L.Play,
  check: L.Check,
  rotateCcw: L.RotateCcw,
  sparkles: L.Sparkles,
  refresh: L.RefreshCcw,
  xCircle: L.XCircle,
  alertCircle: L.AlertCircle,
  compass: L.Compass,
  searchX: L.SearchX,
  fileQuestion: L.FileQuestion,
  serverCrash: L.ServerCrash,
  messageSquare: L.MessageSquare,
  clipboardCheck: L.ClipboardCheck,
  listChecks: L.ListCheck,
  logIn: L.LogIn,
  headphones: L.HeadphoneOff,
  shieldAlert: L.ShieldAlert,
  uploadCloud: L.UploadCloud,
  loaderCircle: L.LoaderCircle,
  trash2: L.Trash2,

  pilcrow: L.Pilcrow,
  minus: L.Minus,
  folderTabs: L.FolderTree,
  milestone: L.Milestone,
  mousePointerClick: L.MousePointerClick,
  star: L.Star,
  handHeart: L.HandHeart,
  chevronsUpDown: L.ChevronsUpDown,
  fileSearch: L.FileSearch,
  archive: L.Archive,
  percent: L.Percent,
  toggleLeft: L.ToggleLeft,
  upload: L.Upload,
  fileEdit: L.FileEdit,
  calendarX2: L.CalendarX2,
  save: L.Save,
  shieldX: L.ShieldX,
  key: L.Key,
  refreshCw: L.RefreshCw,

} as const;

export type IconName = keyof typeof ICON_MAP;
